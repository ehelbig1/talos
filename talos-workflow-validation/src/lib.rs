//! Workflow validation service.
//!
//! Extracted from the `validate_workflow` MCP handler so the same checks can be
//! applied automatically during `publish_version` and after `hot_update_module`.

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use talos_workflow_repository::{NodeTemplateRow, WorkflowRepository};

// Re-use the vault path permission check from the MCP module.
use talos_workflow_job_protocol::vault_path_permitted as _vpp;

// ── Fuel sizing (authoring-time) ─────────────────────────────────────────────
//
// WHY THIS IS A VALIDATION WARNING AND NOT A STRUCTURAL LINT.
// `scripts/lint-structural.sh` reads repository FILES. Workflow graphs live in
// `workflows.graph_json`, authored at runtime through MCP / GraphQL / the
// editor — a structural lint cannot see a single one of them. The only
// repo-resident graphs are the handful of seeds in `workflow-templates/`, so a
// lint would gate ~6 documents and miss every workflow an operator actually
// runs, including the one that motivated this. Validation runs where the graph
// is: `WorkflowValidationService::validate` is called by `validate_workflow`,
// by `publish_version`, and after `hot_update_module`, so the check fires on
// authoring, on publish, and on module change.
//
// WHAT IT CLAIMS, narrowly. A node that generates up to `MAX_TOKENS` of output
// needs a fuel budget that can pay for generating them. If its effective
// ceiling cannot cover its OWN CONFIGURED MAXIMUM, it is mis-sized before it
// has ever run — which is the one dead zone no estimator over past runs can
// reach, because there are no past runs. `pa-read-later-digest/digest` was
// under-provisioned from execution #1.
//
// It does NOT claim to predict consumption. It is a FLOOR, and it is silent
// about everything above the floor: a node that clears it can still be
// under-provisioned for its inputs. `TalosFuelHeadroomLow` is the surface for
// that half, and the two are complementary — the detector needs history and
// this needs none.

/// Fuel a node must be able to spend per token of configured maximum output.
///
/// **Calibrated against the live fleet, not assumed** (2026-08-17). Every
/// workflow node carrying both a `MAX_TOKENS` and an explicit
/// `data.max_fuel` — thirteen of them, i.e. every node an author has
/// deliberately sized — yields `max_fuel / MAX_TOKENS` between **4,444**
/// (`pa-daily-brief/brief`, 8,000,000 / 1800) and **11,429**
/// (`pa-quality-judge/judge`). The node this check exists for sat at
/// **1,002** (1,404,000 / 1400) before #642 raised it.
///
/// So 3,000 sits in an empty band 4.4× wide: nothing on the fleet lies between
/// 1,002 and 4,444. It is a threshold, not a fitted parameter — moving it
/// anywhere inside that band changes no verdict on any node that exists.
pub const FUEL_PER_MAX_TOKEN: u64 = 3_000;

/// Fuel allowance per byte of `__actor_context__` the engine may inject into a
/// memory-eligible node's input, on top of its upstream payload.
///
/// **This is the weakest number in this file and is deliberately not
/// load-bearing.** There is no measurement anywhere in the platform of the
/// fuel cost of an injected context byte, and inventing a precise one from the
/// single available anchor would be a model fitted to one sample. What can be
/// said honestly: at the 12,000-byte default the allowance is 480,000 fuel —
/// about 8% of a typical node's floor — and **removing it entirely changes the
/// verdict on no node of the current fleet, in either direction** (pinned by
/// `the_injection_allowance_is_a_margin_not_a_classifier`). It is a stated
/// margin that keeps the check from pretending the injection is free, not a
/// calibration anything depends on. If it ever starts driving verdicts, it
/// needs a real measurement first.
pub const FUEL_PER_CONTEXT_BYTE: u64 = 40;

/// The minimum fuel a node needs to cover its own configured maximum output,
/// plus — for a memory-eligible node — the `__actor_context__` injection.
///
/// `context_byte_budget` is `SMART_MEMORY_CONTEXT_BYTE_BUDGET` (12,000 default)
/// and is passed in rather than read from the environment so this stays pure
/// and testable. Pass `0` for a node that receives no injection.
///
/// The injection term matters disproportionately relative to its size because
/// it is **invisible in `module_executions.input_data`** — a node sized from
/// its own recorded input is sized short by up to the whole budget, and the
/// recorded input is where an author naturally looks.
#[must_use]
pub fn required_fuel_floor(max_tokens: u64, context_byte_budget: u64) -> u64 {
    max_tokens
        .saturating_mul(FUEL_PER_MAX_TOKEN)
        .saturating_add(context_byte_budget.saturating_mul(FUEL_PER_CONTEXT_BYTE))
}

/// Whether a node in `capability_world` receives `__actor_context__` by
/// default, honouring an explicit per-node `needs_memory`.
///
/// Mirrors `ParallelWorkflowEngine::node_needs_memory_for_world`: the pure-
/// egress worlds (`http` / `network` / `messaging`) default to NO memory, every
/// other world defaults to memory, and an explicit `needs_memory` in node
/// config always wins. Kept in agreement with the engine deliberately — a
/// sizing check that disagreed with the injector about which nodes get the
/// injection would be sizing the wrong nodes.
///
/// An UNKNOWN world (`None`) is treated as memory-eligible. That is the
/// conservative direction for a floor: assuming the injection happens can only
/// raise the required budget, and over-provisioning a node costs nothing at
/// runtime (fuel is a ceiling, not an allocation), while under-provisioning is
/// the failure this exists to prevent.
#[must_use]
pub fn node_receives_actor_context(capability_world: Option<&str>, explicit: Option<bool>) -> bool {
    match explicit {
        Some(v) => v,
        None => capability_world
            .map(|w| !talos_capability_world::world_defaults_no_memory(w))
            .unwrap_or(true),
    }
}

// ── Retry envelope vs the workflow budget containing it ─────────────────────
//
// Every timeout / retry allowance in the platform is already capped against an
// ABSOLUTE constant by `talos_workflow_types::validate_graph_timeouts` — the
// workflow budget against 3600 s, per-node `timeout_secs` against 600 s,
// `retry_count` against 100, `retry_backoff_ms` against its own ceiling. Eight
// independent ceilings, and not one of them compares an allowance against the
// container it has to fit inside.
//
// So a node can be configured with a retry envelope larger than the entire
// workflow budget. The engine will honour it literally: the retry loop
// (`talos-workflow-engine-nats::execute_job_with_retry`) terminates only on
// `attempts > max_retries` and has no deadline parameter at all, while the
// workflow budget is an OUTER `tokio::time::timeout` that DROPS the whole
// reactor future when it fires. Nothing connects the two. An attempt that
// cannot possibly finish is started anyway, runs until the budget expires, and
// takes every already-completed sibling node's result down with it — those
// results live only in the dropped future (per-node checkpointing is opt-in and
// off).
//
// Observed live 2026-08-27: a node with a 120 s per-attempt timeout and
// `retry_count: 2` inside a 300 s budget started its third attempt at t=252 s
// with 48 s left. It could not have completed under any outcome. Two completed
// sibling nodes were discarded.
//
// WHAT THIS CHECK CLAIMS, narrowly: at least one CONFIGURED attempt of this
// node can never complete, whatever else the graph does. That is provable from
// the single node — it needs no assumption about what runs in parallel.
//
// It deliberately does NOT flag the (larger) population where the SUM of
// envelopes along the critical path exceeds the budget. That shape assumes
// every node on the path burns its full envelope simultaneously; it is a real
// worst case but it is not reachable in any observed run, and on the live fleet
// it would fire on a clear majority of workflows that all work today. A warning
// that fires on the majority is a warning nobody reads.

/// Worst-case wall-clock seconds a node's configured retry envelope can occupy:
/// every attempt running to its full per-attempt timeout, plus the exponential
/// backoff slept between them.
///
/// `retries` is the ALREADY-RESOLVED count (an author's declared `retry_count`,
/// or `default_max_retries_for_module` when the author declared none) — this
/// function never invents one, matching `RetryPolicy::resolved_max_retries`.
///
/// Backoff mirrors the dispatcher's `base_backoff_ms * 2^(n-1)` per retry,
/// summing to `base * (2^retries - 1)`. Jitter (up to +25 % per sleep) and the
/// dispatcher's 5 s per-attempt Tokio grace are BOTH excluded, so the result is
/// a lower bound on the true envelope: this check under-reports rather than
/// false-positives.
///
/// **Every step saturates.** `retry_count` is capped at 100, and `2^100` does
/// not fit in a `u64` — an envelope calculator that overflowed while computing
/// whether an allowance fits its container would be an exceptionally poor joke.
#[must_use]
pub fn node_retry_envelope_secs(
    per_attempt_timeout_secs: u64,
    retries: u32,
    base_backoff_ms: u64,
) -> u64 {
    let attempts = u64::from(retries).saturating_add(1);
    let attempt_secs = per_attempt_timeout_secs.saturating_mul(attempts);
    // sum(base * 2^(i-1)) for i in 1..=retries  ==  base * (2^retries - 1)
    let growth = if retries >= 64 {
        u64::MAX
    } else {
        (1u64 << retries) - 1
    };
    let backoff_secs = base_backoff_ms.saturating_mul(growth) / 1_000;
    attempt_secs.saturating_add(backoff_secs)
}

/// Read a node's per-attempt timeout the way the engine does:
/// `data.timeout_secs` first, then top-level, then
/// `DEFAULT_NODE_TIMEOUT_SECS`.
///
/// The precedence is `data`-first and that is NOT a typo — it is the OPPOSITE
/// of `retry_count`, which the engine reads top-level-first. Mirroring each
/// key's own order is the whole point; a checker that guessed one order for
/// both would silently disagree with the engine on any node that sets both
/// shapes.
fn node_per_attempt_timeout_secs(node: &serde_json::Value, default_secs: u64) -> u64 {
    node.get("data")
        .and_then(|d| d.get("timeout_secs"))
        .or_else(|| node.get("timeout_secs"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(default_secs)
}

/// Read a node's declared `retry_count` / `retry_backoff_ms` the way
/// `read_node_retry_policy` does: top-level first, then under `data`.
fn node_declared_u64(node: &serde_json::Value, key: &str) -> Option<u64> {
    node.get(key)
        .or_else(|| node.get("data").and_then(|d| d.get(key)))
        .and_then(serde_json::Value::as_u64)
}

/// A node whose configured retry envelope cannot fit its workflow's budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryEnvelopeOverrun {
    /// Worst-case seconds the node's attempts + backoff can occupy.
    pub envelope_secs: u64,
    /// Total attempts the engine is configured to make (`retries + 1`).
    pub attempts: u64,
    /// Per-attempt timeout the engine will enforce.
    pub per_attempt_secs: u64,
    /// Resolved retry count — declared, clamped, or classifier-supplied.
    pub resolved_retries: u32,
    /// `true` when the count came from the node's own `retry_count`;
    /// `false` when the method-aware module default supplied it.
    pub retries_declared: bool,
}

/// Decide whether one node's retry envelope exceeds the workflow budget that
/// contains it. `None` means it fits (or there is no budget to fit inside).
///
/// Pure, so the fire / don't-fire decision is unit-tested against the real
/// shapes rather than shadowed by a test-local reimplementation. `validate`
/// calls this and only formats the message.
///
/// `budget_secs == 0` means the workflow-level wall-clock cap is DISABLED —
/// there is no container, so nothing can exceed it.
#[must_use]
pub fn retry_envelope_overrun(
    node: &serde_json::Value,
    budget_secs: u64,
    has_actor: bool,
    module_methods: &[String],
    module_world: Option<&str>,
    default_node_timeout_secs: u64,
) -> Option<RetryEnvelopeOverrun> {
    if budget_secs == 0 {
        return None;
    }
    let declared =
        node_declared_u64(node, "retry_count").map(|v| u32::try_from(v).unwrap_or(u32::MAX));
    let resolved_retries = match declared {
        Some(n) if has_actor => n,
        // An actor-less execution has its DECLARED count clamped at graph load;
        // predicting the unclamped one would report an envelope that cannot run.
        Some(n) => n.min(talos_workflow_engine_core::MAX_RETRIES_UNBUDGETED),
        None => {
            talos_workflow_engine_core::default_max_retries_for_module(module_methods, module_world)
        }
    };
    let per_attempt_secs = node_per_attempt_timeout_secs(node, default_node_timeout_secs);
    let backoff_ms = node_declared_u64(node, "retry_backoff_ms")
        .unwrap_or(talos_workflow_engine_core::DEFAULT_BACKOFF_MS);
    let envelope_secs = node_retry_envelope_secs(per_attempt_secs, resolved_retries, backoff_ms);
    if envelope_secs <= budget_secs {
        return None;
    }
    Some(RetryEnvelopeOverrun {
        envelope_secs,
        attempts: u64::from(resolved_retries).saturating_add(1),
        per_attempt_secs,
        resolved_retries,
        retries_declared: declared.is_some(),
    })
}

// ── Observed failure history (authoring-time, Warning-only) ──────────────────
//
// WHY THIS EXISTS.
// `validate_workflow` answered `valid: true, issues: []` for a live workflow
// that had failed roughly a third of its runs for weeks — four consecutive
// daily failures, every one of them on the same node, every one a timeout.
// The same response printed "Improve success rate — currently 68.2%" as a soft
// suggestion, so the platform HAD the signal and simply did not connect it to
// `issues`. An operator reading `issues: []` concludes the workflow is fine.
//
// That is the misleading-report class: a field named `valid` carrying a
// verdict narrower than the name implies, while the data needed to say
// something true sits in the same response.
//
// WHY EVERY FINDING HERE IS A `Warning` AND NEVER AN `Error`.
// `ValidationResult::valid` is `false` iff an Error exists, and `valid` gates
// `publish_version`. If a bad week could set `valid = false`, a workflow would
// become unpublishable because of its operational history — including the case
// where the operator is publishing THE FIX for exactly those failures. That is
// a worse failure than the silence being fixed here: it is unrecoverable
// through the tool, whereas an under-stated warning is merely quiet. History
// describes what happened; only configuration can make a graph invalid.
//
// WHAT IT CLAIMS, NARROWLY. Two independent statements, kept separate on
// purpose:
//   1. an OBSERVATION — this node failed N of M observed attempts in a bounded
//      window, and K of those N named a timeout; and
//   2. a STATIC FACT about the graph as it is RIGHT NOW — the retries the
//      engine will resolve for that node, and whether one more attempt could
//      even fit the workflow budget.
// It does not claim (2) caused (1). It cannot: the configuration may have
// changed inside the window (on the workflow that motivated this, the node's
// `timeout_secs` went 30 -> 110 partway through), and a node can fail for
// reasons no graph inspection can see. The message says both things and lets
// the operator join them.

/// How far back the history slice may reach, in days.
///
/// Pinned to the execution-retention default rather than chosen freely:
/// `execution_events` rows CASCADE from `workflow_executions`, which the
/// retention sweep DELETEs after `EXECUTION_RETENTION_DAYS` (default 30). A
/// longer lookback cannot return older data — it would just be a window that
/// silently shrinks to whatever retention happens to be, which is the trap
/// this check must not fall into. [`history_window_days`] narrows it further
/// when an operator has configured a shorter retention, so the window is never
/// wider than the store can actually hold.
pub const HISTORY_WINDOW_DAYS: i32 = 30;

/// Hard cap on executions in the slice, independent of cadence.
///
/// The day window alone is not a bound: a 15-minute poller produces ~2,900
/// executions in 30 days. 50 keeps the row count bounded (measured: 3.7 ms on
/// a 4,525-execution workflow, the same work as on a 26-execution one).
///
/// **The trade, stated plainly.** On a daily workflow 50 covers the entire
/// retention window. On a high-frequency one it covers roughly the last twelve
/// hours, so the check is strongly recency-biased there and will stay quiet
/// about a chronic-but-rare failure that a 30-day view would surface. That is
/// the deliberate direction: a high-frequency workflow's last 50 runs reflect
/// its CURRENT configuration, and a warning about a config that no longer
/// exists is worse than no warning.
pub const HISTORY_MAX_EXECUTIONS: i64 = 50;

/// Minimum `node_failed` count before a node is called chronically failing.
///
/// Two failures can be one incident — a provider outage spanning two runs of a
/// daily workflow reads identically to a persistent defect. Three separated
/// failures is the smallest count that distinguishes a pattern from an
/// incident. The cost of raising it is latency: on a daily workflow every +1
/// is another day of silence.
pub const CHRONIC_MIN_FAILURES: i64 = 3;

/// Minimum observed attempts before a RATE is computed at all.
///
/// Guards against publishing a percentage derived from a denominator too small
/// to mean anything (3 failures in 4 attempts is 75 %, and also just four data
/// points). It also suppresses the system-node dispatch paths that emit
/// `node_failed` with no preceding `node_started`, where the only available
/// denominator is the failure itself.
pub const CHRONIC_MIN_ATTEMPTS: i64 = 5;

/// Minimum observed failure rate, as a fraction of attempts.
///
/// **Calibrated against the live fleet, not assumed** (2026-08-28). Over the
/// 30-day event history, the per-node failure rates of every node with at
/// least [`CHRONIC_MIN_FAILURES`] failures are: 28.6 % (`daily-crm-capture` /
/// `extract` — the node this check exists for), 15.4 %
/// (`pa-autonomy-digest` / `compose`), then 1.3 %, 0.9 %, 0.4 %, 0.3 %. The
/// band between 1.3 % and 15.4 % is 12x wide and empty: any threshold inside
/// it selects the same two nodes and rejects the same four, so 10 % is a
/// threshold, not a fitted parameter.
///
/// The four rejected nodes are high-volume workflows (230–4,525 runs) where a
/// handful of absolute failures is ordinary background; without this gate
/// their absolute counts would clear [`CHRONIC_MIN_FAILURES`] on the raw
/// 30-day view. Both gates are load-bearing.
pub const CHRONIC_FAILURE_RATE: f64 = 0.10;

/// The lookback to use, never wider than the store can hold.
///
/// Reads `EXECUTION_RETENTION_DAYS` so a cluster configured to keep 7 days is
/// described as a 7-day window instead of a 30-day one that quietly contains 7.
#[must_use]
pub fn history_window_days() -> i32 {
    HISTORY_WINDOW_DAYS.min(talos_config::execution_retention_days())
}

/// What the history read actually covered. Carried on every
/// [`ValidationResult`] so an empty `issues` list is never ambiguous.
///
/// The three variants exist because "no findings" has three very different
/// causes and collapsing them is the bug this whole module addresses. In
/// particular [`Unavailable`](Self::Unavailable) must never render as
/// [`Empty`](Self::Empty): a failed read reported as "nothing there" is the
/// error-as-absence shape (`get_schedule_health` returning zeros; #661).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryCoverage {
    /// History was read and the window held executions.
    Observed {
        /// Executions inspected (cancelled and test runs already excluded).
        executions: i64,
        /// Lookback in days.
        window_days: i32,
    },
    /// History was read and the window held nothing. The static checks ran;
    /// the history checks had no input. This is NOT evidence of health.
    Empty {
        /// Lookback in days.
        window_days: i32,
    },
    /// The history read failed. No history check ran, and this result says
    /// nothing at all about the workflow's operational record.
    Unavailable,
}

impl HistoryCoverage {
    /// One sentence naming what was and was not examined, for rendering
    /// alongside `valid` / `issues`.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            Self::Observed {
                executions,
                window_days,
            } => format!(
                "Execution history consulted: {executions} run(s) in the last {window_days} \
                 day(s), excluding cancelled and test executions."
            ),
            Self::Empty { window_days } => format!(
                "No execution history in the last {window_days} day(s) — these findings are \
                 STATIC ONLY. An empty issues list here means nothing has been observed, not \
                 that the workflow runs cleanly."
            ),
            Self::Unavailable => "Execution history could NOT be read — history-based checks \
                                  did not run. An empty issues list here says nothing about \
                                  this workflow's operational record."
                .to_string(),
        }
    }

    /// `true` when history-based findings were actually possible.
    #[must_use]
    pub fn consulted(&self) -> bool {
        matches!(self, Self::Observed { .. })
    }
}

/// The static half of a chronic-failure finding: what the engine will do on
/// the NEXT run, derived from the graph alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryHeadroom {
    /// Retries the engine resolves for this node — declared, clamped, or the
    /// method-aware module default.
    pub resolved_retries: u32,
    /// `true` when the node declares its own `retry_count` (including an
    /// explicit `0`, which always wins); `false` when the module default
    /// supplied it.
    pub retries_declared: bool,
    /// Per-attempt timeout the engine enforces.
    pub per_attempt_secs: u64,
    /// The workflow's enforced wall-clock budget.
    pub budget_secs: u64,
    /// Worst-case seconds the node's CURRENT configuration can occupy
    /// (`resolved_retries + 1` attempts plus backoff).
    pub current_envelope_secs: u64,
    /// Budget left over after the current envelope. This is the room available
    /// for raising `timeout_secs` without any other change — `0` when the node
    /// already fills or overruns its budget (the overrun case is
    /// [`retry_envelope_overrun`]'s to report, not this one's).
    pub spare_secs: u64,
    /// Worst-case seconds if the node were given ONE more attempt than it
    /// currently resolves to.
    pub one_more_attempt_secs: u64,
    /// `false` when that extra attempt could not fit the budget — i.e. raising
    /// `retry_count` alone cannot help this node.
    pub one_more_attempt_fits: bool,
}

/// Compute the retry headroom for a node, using the SAME resolution rules the
/// engine applies (and that [`retry_envelope_overrun`] applies) so the two
/// checks can never disagree about what a node's retry count is.
///
/// `budget_secs == 0` means the workflow wall-clock cap is disabled; there is
/// no container, so headroom is unbounded and this returns `None`.
#[must_use]
pub fn retry_headroom(
    node: &serde_json::Value,
    budget_secs: u64,
    has_actor: bool,
    module_methods: &[String],
    module_world: Option<&str>,
    default_node_timeout_secs: u64,
) -> Option<RetryHeadroom> {
    if budget_secs == 0 {
        return None;
    }
    let declared =
        node_declared_u64(node, "retry_count").map(|v| u32::try_from(v).unwrap_or(u32::MAX));
    let resolved_retries = match declared {
        Some(n) if has_actor => n,
        Some(n) => n.min(talos_workflow_engine_core::MAX_RETRIES_UNBUDGETED),
        None => {
            talos_workflow_engine_core::default_max_retries_for_module(module_methods, module_world)
        }
    };
    let per_attempt_secs = node_per_attempt_timeout_secs(node, default_node_timeout_secs);
    let backoff_ms = node_declared_u64(node, "retry_backoff_ms")
        .unwrap_or(talos_workflow_engine_core::DEFAULT_BACKOFF_MS);
    let current_envelope_secs =
        node_retry_envelope_secs(per_attempt_secs, resolved_retries, backoff_ms);
    let one_more_attempt_secs = node_retry_envelope_secs(
        per_attempt_secs,
        resolved_retries.saturating_add(1),
        backoff_ms,
    );
    Some(RetryHeadroom {
        resolved_retries,
        retries_declared: declared.is_some(),
        per_attempt_secs,
        budget_secs,
        current_envelope_secs,
        spare_secs: budget_secs.saturating_sub(current_envelope_secs),
        one_more_attempt_secs,
        one_more_attempt_fits: one_more_attempt_secs <= budget_secs,
    })
}

/// One node's observed record over the history window, as the classifier
/// consumes it. Plain scalars so the decision is testable without a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedNodeRecord {
    /// Denominator — `greatest(started, completed + failed)`.
    pub attempts: i64,
    /// `node_failed` events (never `attempts - completed`; see
    /// `WorkflowRepository::node_run_history`).
    pub failures: i64,
    /// Subset of `failures` whose message named a timeout.
    pub timeout_failures: i64,
}

/// A node whose observed failure record clears the chronic thresholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChronicNodeFailure {
    /// The observation.
    pub observed: ObservedNodeRecord,
    /// Executions the window covered, for stating the sample.
    pub executions_scanned: i64,
    /// Lookback in days.
    pub window_days: i32,
    /// The static half — `None` for a system node (no module dispatch, so
    /// per-attempt timeouts and module retry defaults do not apply) or when
    /// the workflow budget is disabled.
    pub headroom: Option<RetryHeadroom>,
}

/// Decide whether an observed record is a chronic failure worth reporting.
///
/// Pure, so the fire / don't-fire decision is tested against real fleet
/// numbers rather than shadowed by a test-local reimplementation. `validate`
/// calls this and [`describe_chronic_failure`]; it makes no decision itself.
///
/// Returns `None` unless ALL of:
/// * at least [`CHRONIC_MIN_FAILURES`] failures,
/// * at least [`CHRONIC_MIN_ATTEMPTS`] attempts, and
/// * a failure rate of at least [`CHRONIC_FAILURE_RATE`].
#[must_use]
pub fn chronic_node_failure(
    observed: &ObservedNodeRecord,
    executions_scanned: i64,
    window_days: i32,
    headroom: Option<RetryHeadroom>,
) -> Option<ChronicNodeFailure> {
    if observed.failures < CHRONIC_MIN_FAILURES || observed.attempts < CHRONIC_MIN_ATTEMPTS {
        return None;
    }
    // `attempts >= CHRONIC_MIN_ATTEMPTS` above rules out a zero denominator.
    #[allow(clippy::cast_precision_loss)]
    let rate = observed.failures as f64 / observed.attempts as f64;
    if rate < CHRONIC_FAILURE_RATE {
        return None;
    }
    Some(ChronicNodeFailure {
        observed: observed.clone(),
        executions_scanned,
        window_days,
        headroom,
    })
}

/// Render the operator-facing text for a chronic-failure finding.
///
/// Separate from the decision so the exact wording is pinned by tests. The
/// observation and the static configuration facts are rendered as separate
/// sentences and never joined by a causal claim.
#[must_use]
pub fn describe_chronic_failure(finding: &ChronicNodeFailure, node_label: &str) -> String {
    let ChronicNodeFailure {
        observed:
            ObservedNodeRecord {
                attempts,
                failures,
                timeout_failures,
            },
        executions_scanned,
        window_days,
        headroom,
    } = finding;

    let timeout_clause = if *timeout_failures == *failures {
        ", every one of them a timeout".to_string()
    } else if *timeout_failures > 0 {
        format!(", {timeout_failures} of them timeouts")
    } else {
        String::new()
    };

    let mut msg = format!(
        "Node '{node_label}' failed {failures} of its last {attempts} observed attempts\
         {timeout_clause} (across {executions_scanned} execution(s) in the last {window_days} \
         day(s), excluding cancelled and test runs). This is an OBSERVATION about runs that \
         already happened, not a claim that the current graph caused them — the node's config \
         may have changed inside that window."
    );

    if let Some(h) = headroom {
        let retry_note = if h.retries_declared {
            format!(
                "its retry_count is explicitly {} (an explicit value always wins over the \
                 module default)",
                h.resolved_retries
            )
        } else {
            format!(
                "it declares no retry_count, so the method-aware module default resolves to {}",
                h.resolved_retries
            )
        };
        msg.push_str(&format!(
            " Statically, as the graph stands now: {retry_note}, and its per-attempt timeout is \
             {}s, inside a {}s workflow budget.",
            h.per_attempt_secs, h.budget_secs
        ));

        // Retries first — whether that lever is even available is the single
        // most useful fact, and it is a fact about the graph, not a guess.
        if h.one_more_attempt_fits {
            msg.push_str(&format!(
                " One more attempt would occupy ~{}s of that budget, so raising retry_count is \
                 available IF the failures are transient.",
                h.one_more_attempt_secs
            ));
        } else {
            msg.push_str(&format!(
                " One more attempt would need ~{}s, so NO retry fits — raising retry_count alone \
                 cannot help this node.",
                h.one_more_attempt_secs
            ));
        }

        // Then the timeout lever, sized from the ACTUAL unused budget rather
        // than waved at. A blanket "do not raise timeout_secs" would be wrong
        // here: at {attempts} attempt(s) there is real room, and telling an
        // operator not to use it is worse than saying nothing.
        if *timeout_failures > 0 {
            if h.spare_secs > 0 {
                msg.push_str(&format!(
                    " Since the failures are timeouts: the current envelope is ~{}s, leaving \
                     ~{}s of the budget unused, so timeout_secs can be raised into that room. \
                     Note that raising it is only safe while retry_count stays at {} — each \
                     extra attempt multiplies the envelope. The other levers are making the \
                     node's work smaller (narrower query, lower result cap) and raising \
                     execution_timeout_secs.",
                    h.current_envelope_secs, h.spare_secs, h.resolved_retries
                ));
            } else {
                msg.push_str(
                    " Since the failures are timeouts and the current envelope already fills \
                     the budget, there is no room to raise timeout_secs: make the node's work \
                     smaller (narrower query, lower result cap) or raise execution_timeout_secs.",
                );
            }
        }
    }
    msg
}

// ── Explicitly disabled retry protection ─────────────────────────────────────
//
// `default_max_retries_for_module(allowed_methods, capability_world)` grants
// transient retries to work that CANNOT double-fire a side effect: the
// pure-compute worlds (`minimal` / `secrets`) and `http` / `agent` with a
// DECLARED GET/HEAD-only `allowed_methods`. Everything else — governance,
// messaging, database, unknown worlds, state-changing HTTP — already fails
// closed to 0. That asymmetry is the whole gate here: a node whose world
// resolves to 0 anyway is correctly configured and must stay silent.
//
// An explicit per-node `retry_count` always wins over that default, including
// an explicit `0`. So a node can carry `retry_count: 0` on a read-only world
// and run EXACTLY ONCE — a single DNS blip fails the whole execution — while
// its sibling on the identical module retries twice. Nothing in the platform
// says so today: an explicit 0 is a valid configuration, it produces no
// runtime error, and it looks like every other node until the day it doesn't.
// That is what this check reports.
//
// WHAT IT DOES NOT DO. It does not claim the 0 is wrong, and nothing here
// mutates a graph. An explicit 0 has legitimate uses on exactly these worlds:
// a retry re-runs the node's work, and where that work costs money (an LLM
// completion, a metered API call) each attempt pays again — a timeout is
// classified transient, so a retry fires even when the first attempt may have
// completed and been billed. The finding states the fact and the cost, and
// leaves the decision with the operator. It is a Warning for the same reason
// every finding above it is: `valid == false` gates `publish_version`, and a
// configuration opinion must never make a workflow unpublishable.
//
// WHY IT DOES NOT WAIT FOR A FAILURE. Gating on observed failures would make
// this a lagging indicator, which is the exact defect the method-aware default
// was introduced to remove — the blanket-0 era was invisible until an outage
// failed ~125 read-only fetches at once. A node that has never run has the
// same dead retry as one that has run 4,500 times. Observed history is
// therefore DECORATION on the finding, not its trigger: it is rendered when it
// exists because "and its most recent failure was transient" is what turns a
// configuration note into a decision, and omitted when it does not.

/// A node that explicitly disables a retry protection its module's world would
/// otherwise grant.
///
/// Every field is descriptive — the numbers come from
/// [`talos_workflow_engine_core::default_max_retries_for_module`] and from the
/// module row, never from a rule restated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisabledRetryProtection {
    /// What `default_max_retries_for_module` resolves for this node's module.
    /// Always `> 0` — a module whose default is already 0 does not produce a
    /// finding.
    pub world_default_retries: u32,
    /// The module's capability world, quoted verbatim so the message names the
    /// input to the default rather than re-deriving why it applied.
    pub capability_world: Option<String>,
    /// The module's declared `allowed_methods`, likewise verbatim. Empty for
    /// the pure-compute worlds, which do not declare any.
    pub allowed_methods: Vec<String>,
}

/// Decide whether a node has explicitly disabled retries its world would grant.
///
/// Pure, so the fire / don't-fire decision is tested against real fleet
/// configurations rather than shadowed by a test-local reimplementation.
///
/// Returns `None` unless BOTH:
/// * the node declares `retry_count` and it is exactly `0` — an ABSENT
///   `retry_count` is the healthy case (the default applies); and
/// * [`talos_workflow_engine_core::default_max_retries_for_module`] resolves
///   `> 0` for this module's `allowed_methods` + `capability_world`.
///
/// The second condition is the entire noise gate and is delegated, never
/// reimplemented: side-effecting worlds already resolve to 0, so a finding on
/// one would be reporting agreement with the default as if it were a problem.
///
/// `retry_count` is read with the same top-level-then-`data` precedence the
/// engine and [`retry_envelope_overrun`] use, so the three can never disagree
/// about what a node declared.
#[must_use]
pub fn disabled_retry_protection(
    node: &serde_json::Value,
    module_methods: &[String],
    module_world: Option<&str>,
) -> Option<DisabledRetryProtection> {
    if node_declared_u64(node, "retry_count")? != 0 {
        return None;
    }
    let world_default_retries =
        talos_workflow_engine_core::default_max_retries_for_module(module_methods, module_world);
    if world_default_retries == 0 {
        return None;
    }
    Some(DisabledRetryProtection {
        world_default_retries,
        capability_world: module_world.map(str::to_string),
        allowed_methods: module_methods.to_vec(),
    })
}

/// Whether retry intelligence classifies a node's most recent recorded failure
/// message as transient — i.e. whether the retry this node does not have would
/// have been ATTEMPTED at all, rather than skipped as permanent.
///
/// Delegates to the same `classify_error` + `is_transient_error_type` pair the
/// dispatcher's smart-retry gate uses
/// (`talos-workflow-engine-nats::dispatcher`), so the answer cannot drift from
/// the runtime decision it describes.
///
/// `None` when there is no recorded failure message to classify. Note the
/// input is `execution_events.log_message` — the operator-visible record of
/// the failure — whereas the dispatcher classifies the job result's `error`
/// field at the moment it decides. The two are the same failure but not
/// guaranteed to be the same string, which is why the rendered text calls this
/// a classification of the RECORDED message.
#[must_use]
pub fn latest_failure_is_transient(latest_error: Option<&str>) -> Option<bool> {
    let msg = latest_error?;
    Some(talos_retry_intelligence::is_transient_error_type(
        &talos_retry_intelligence::classify_error(msg),
    ))
}

/// Render the operator-facing text for a disabled-retry-protection finding.
///
/// Separate from the decision so the exact wording is pinned by tests. The
/// static configuration fact, the observed record, and the reason an operator
/// might legitimately keep the `0` are rendered as separate sentences and never
/// joined by a causal claim.
///
/// `observed` decorates the finding when the node ran inside the history
/// window; absence of history never suppresses it (see the module note above).
#[must_use]
pub fn describe_disabled_retry_protection(
    finding: &DisabledRetryProtection,
    node_label: &str,
    observed: Option<&ObservedNodeRecord>,
    latest_failure_transient: Option<bool>,
    executions_scanned: i64,
    window_days: i32,
) -> String {
    let DisabledRetryProtection {
        world_default_retries,
        capability_world,
        allowed_methods,
    } = finding;

    // Name the module's declared inputs rather than restating the rule that
    // consumed them — the rule lives in `default_max_retries_for_module` and
    // must have exactly one statement in the codebase.
    let world = capability_world.as_deref().unwrap_or("unknown");
    let methods_clause = if allowed_methods.is_empty() {
        String::new()
    } else {
        format!(", allowed_methods [{}]", allowed_methods.join(", "))
    };

    let mut msg = format!(
        "Node '{node_label}' sets retry_count explicitly to 0, which disables retries. Its \
         module (capability world '{world}'{methods_clause}) resolves to {world_default_retries} \
         transient retries by default, and an explicit value always wins over that default — so \
         this node runs EXACTLY ONCE and a transient failure (DNS, TLS, connection reset, \
         timeout) fails the execution on the first attempt."
    );

    if let Some(ObservedNodeRecord {
        attempts, failures, ..
    }) = observed
    {
        if *failures > 0 {
            msg.push_str(&format!(
                " Observed: {failures} of its last {attempts} attempts failed (across \
                 {executions_scanned} execution(s) in the last {window_days} day(s), excluding \
                 cancelled and test runs)."
            ));
            match latest_failure_transient {
                Some(true) => msg.push_str(
                    " The most recent of those failures classifies as TRANSIENT from its \
                     recorded message, so a retry would have been attempted had one been \
                     configured.",
                ),
                Some(false) => msg.push_str(
                    " The most recent of those failures classifies as permanent from its \
                     recorded message, so a retry would have been skipped anyway — retries are \
                     not the lever for that failure.",
                ),
                None => {}
            }
        } else {
            msg.push_str(&format!(
                " Observed: it has not failed in its last {attempts} attempts (across \
                 {executions_scanned} execution(s) in the last {window_days} day(s)), so this is \
                 a note about exposure, not a report of damage."
            ));
        }
    }

    msg.push_str(&format!(
        " If the 0 is deliberate, keep it: a retry re-runs the node's work, and where that work \
         has a cost (an LLM completion, a metered API call) each attempt pays it again — a \
         timeout counts as transient, so a retry can fire even when the first attempt may have \
         completed. If it is not deliberate, set retry_count to {world_default_retries} — the \
         value the module default already resolves to."
    ));

    msg
}
// ── Types ────────────────────────────────────────────────────────────────────

/// Severity of a validation issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationSeverity {
    /// Blocks publication — the workflow will fail at runtime.
    Error,
    /// Informational — the workflow may work, but there is a concern.
    Warning,
}

/// A single validation finding.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub severity: ValidationSeverity,
    pub message: String,
    pub node_id: Option<String>,
    pub category: String,
}

/// Aggregate result of validating a workflow.
#[derive(Debug)]
pub struct ValidationResult {
    /// `true` when there are zero `Error`-severity issues.
    ///
    /// **Deliberately not influenced by execution history.** Findings in the
    /// `failure-history` category are always `Warning`, so a workflow that has
    /// been failing is still publishable — including when what is being
    /// published is the fix. See the note above [`HISTORY_WINDOW_DAYS`].
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    /// What the execution-history read covered.
    ///
    /// Present so an empty `issues` list is never ambiguous: it distinguishes
    /// "history examined, nothing chronic found" from "no history existed" and
    /// from "the history read failed". Callers rendering `valid` / `issues`
    /// should render [`HistoryCoverage::note`] alongside them.
    pub history: HistoryCoverage,
}

impl ValidationResult {
    pub fn errors(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Error)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&ValidationIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity == ValidationSeverity::Warning)
            .collect()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Detect Rhai expressions that are statically guaranteed to evaluate to
/// `true` — the canonical "infinite loop without an exit condition" pattern.
///
/// MCP-1211 (2026-05-18): added when a workflow's `condition: "true"` loop
/// was silently hitting `max_iterations` on every run with no operator
/// signal. The check is intentionally CONSERVATIVE — a runtime evaluator
/// (Rhai) could prove more truthy expressions but would risk false
/// positives on legitimate dynamic conditions. We flag only forms that a
/// human reader would also call "trivially true":
///
/// * `true` (case-insensitive)
/// * `1` (Rhai integer truthy)
/// * `!false`
///
/// Each may be surrounded by whitespace and any number of matched parens.
/// Multi-token expressions (`x == x`, `1 == 1`, etc.) are intentionally
/// NOT matched — they require a parser to disambiguate from legitimate
/// dynamic checks, and the false-positive risk outweighs the value.
pub(crate) fn is_trivially_true_condition(raw: &str) -> bool {
    // Strip whitespace + balanced enclosing parens until we reach the core.
    let mut s = raw.trim();
    loop {
        if !(s.starts_with('(') && s.ends_with(')')) {
            break;
        }
        // Confirm the leading `(` matches the trailing `)` (not a case like
        // `(a) || (b)` where the outer parens aren't a single group).
        let bytes = s.as_bytes();
        let mut depth: i32 = 0;
        let mut matches_outer = true;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 && i != bytes.len() - 1 {
                        matches_outer = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if !matches_outer {
            break;
        }
        s = s[1..s.len() - 1].trim();
    }
    let lower = s.to_ascii_lowercase();
    matches!(lower.as_str(), "true" | "1" | "!false")
}

// ── Service ──────────────────────────────────────────────────────────────────

pub struct WorkflowValidationService;

impl WorkflowValidationService {
    /// Validate a workflow's graph for structural correctness, module existence,
    /// config completeness, and vault permission compliance.
    ///
    /// Returns `Ok(ValidationResult)` — callers decide how to handle errors vs.
    /// warnings.  Database failures bubble up as `Err`.
    pub async fn validate(
        workflow_repo: &WorkflowRepository,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<ValidationResult> {
        let graph_json_str = workflow_repo
            .get_workflow_graph(workflow_id, user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Workflow not found or access denied"))?;

        let graph: serde_json::Value = serde_json::from_str(&graph_json_str)
            .unwrap_or_else(|_| serde_json::json!({"nodes":[],"edges":[]}));

        let mut issues: Vec<ValidationIssue> = Vec::new();

        let nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default();
        let edges = graph
            .get("edges")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default();

        // ── Module existence (batch) ─────────────────────────────────────
        let module_ids: Vec<Uuid> = nodes
            .iter()
            .filter_map(|n| {
                n.get("type")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
            })
            .collect();

        if !module_ids.is_empty() {
            let existing: HashSet<Uuid> = workflow_repo
                .modules_exist(&module_ids)
                .await
                .unwrap_or_default()
                .into_iter()
                .collect();

            for mid in &module_ids {
                if !existing.contains(mid) {
                    issues.push(ValidationIssue {
                        severity: ValidationSeverity::Error,
                        message: format!(
                            "Module '{}' not found in templates or compiled modules",
                            mid
                        ),
                        node_id: None,
                        category: "missing_module".into(),
                    });
                }
            }
        }

        // ── Graph structure (cycle + edge validation) ────────────────────
        let node_ids: Vec<&str> = nodes
            .iter()
            .filter_map(|n| n.get("id").and_then(|v| v.as_str()))
            .collect();

        let node_index_map: HashMap<&str, usize> = node_ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i))
            .collect();

        let mut digraph = petgraph::graph::DiGraph::<&str, ()>::new();
        let graph_indices: Vec<petgraph::graph::NodeIndex> =
            node_ids.iter().map(|id| digraph.add_node(id)).collect();

        for edge in &edges {
            let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if let (Some(&si), Some(&ti)) = (node_index_map.get(src), node_index_map.get(tgt)) {
                digraph.add_edge(graph_indices[si], graph_indices[ti], ());
            }
        }

        if petgraph::algo::is_cyclic_directed(&digraph) {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Error,
                message: "Graph contains a cycle".into(),
                node_id: None,
                category: "cycle".into(),
            });
        }

        // ── Probable-intent hint: multiple parallel roots (sweep DX
        // finding, 2026-07-07). Multiple nodes with no incoming edges are
        // LEGAL — they all run in parallel from the trigger — but the most
        // common way to arrive here is a typo'd/omitted edge parameter
        // (`depends_on` instead of `connect_from`), which produced a
        // "valid" workflow whose nodes silently ran in parallel instead of
        // chained. Warning severity: never blocks, just asks the question
        // validation is uniquely positioned to ask.
        if node_ids.len() >= 2 {
            let mut has_incoming: HashSet<&str> = HashSet::new();
            for edge in &edges {
                if let Some(tgt) = edge.get("target").and_then(|v| v.as_str()) {
                    has_incoming.insert(tgt);
                }
            }
            let roots: Vec<&str> = node_ids
                .iter()
                .filter(|id| !has_incoming.contains(**id))
                .copied()
                .collect();
            if roots.len() >= 2 {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    message: format!(
                        "{} root nodes ({}) have no incoming edges and will ALL run in \
                         parallel from the trigger. If you intended a sequence, connect \
                         them (add_node_to_workflow's `connect_from`, or an edge in \
                         graph_json). Ignore this if parallel fan-out is intentional.",
                        roots.len(),
                        roots.join(", "),
                    ),
                    node_id: None,
                    category: "parallel_roots".into(),
                });
            }
        }

        let node_id_set: HashSet<&str> = node_ids.iter().copied().collect();
        for edge in &edges {
            let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
            if !node_id_set.contains(src) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    message: format!("Edge source '{}' does not match any node", src),
                    node_id: None,
                    category: "edge".into(),
                });
            }
            if !node_id_set.contains(tgt) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Error,
                    message: format!("Edge target '{}' does not match any node", tgt),
                    node_id: None,
                    category: "edge".into(),
                });
            }
        }

        // Durability advisory (crash-recovery audit): collected inside the
        // template block below, surfaced as a Warning after it.
        let mut side_effecting_node_ids: Vec<String> = Vec::new();

        // ── Config completeness + vault permission check ─────────────────
        // ── Shared inputs for the two history/envelope checks ───────────
        //
        // Hoisted above the module block because BOTH the retry-envelope check
        // (which needs module rows) and the observed-history check (which does
        // not — a workflow of nothing but system nodes still has a record)
        // read them, and neither should pay for its own copy of the actor
        // lookup.
        //
        // The ENFORCED budget is the graph's `execution_timeout_secs`, read by
        // the engine during `load_graph_from_json`, falling back to its 300 s
        // default. It is NOT `workflows.timeout_seconds` — that column is read
        // into `WorkflowRow` and never reaches an engine, and on the live fleet
        // one workflow's column disagrees with its enforced budget by 240 s.
        // Compare against what runs. `0` disables the wall-clock cap entirely.
        let budget = graph
            .get("execution_timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(talos_workflow_engine_core::DEFAULT_WORKFLOW_EXECUTION_TIMEOUT_SECS);

        // An execution with no bound actor has its DECLARED retry count
        // clamped to `MAX_RETRIES_UNBUDGETED` at graph load. Using the
        // unclamped value would over-report an envelope that cannot occur —
        // the one direction a warning must not err in.
        //
        // On a DB failure we assume NO actor, which clamps the predicted count
        // and can only SUPPRESS warnings — never invent one. Logged rather
        // than swallowed: a silently failing query that degrades a check into
        // always-quiet is its own class of bug.
        let has_actor = match workflow_repo
            .get_workflow_actor_id(workflow_id, user_id)
            .await
        {
            Ok(a) => a.is_some(),
            Err(e) => {
                tracing::warn!(
                    %workflow_id,
                    error = %e,
                    "retry-envelope / history check: actor lookup failed; assuming unbound \
                     (clamps predicted retries, so this can only under-report)"
                );
                false
            }
        };

        // Per-module retry inputs, populated by the module block below and
        // read again by the history check after it. Empty for a graph with no
        // module nodes, which is the correct input for both readers.
        let mut template_retry: HashMap<Uuid, (Vec<String>, Option<String>)> = HashMap::new();

        if !module_ids.is_empty() {
            let (template_rows, installed_secrets) = tokio::join!(
                workflow_repo.get_templates_by_ids(&module_ids),
                workflow_repo.get_installed_secrets_by_template_ids(&module_ids, user_id),
            );
            let template_rows: Vec<NodeTemplateRow> = template_rows.unwrap_or_default();
            let installed_secrets: HashMap<Uuid, Vec<String>> =
                installed_secrets.unwrap_or_default();

            // A node whose template declares any `allowed_hosts` makes an external
            // call → potential side effect / cost. On crash-recovery resume an
            // in-flight node is RE-DISPATCHED (at-least-once), so these are the
            // nodes an author must make idempotent.
            let side_effecting_ids: std::collections::HashSet<Uuid> = template_rows
                .iter()
                .filter(|r| !r.allowed_hosts.is_empty())
                .map(|r| r.id)
                .collect();
            side_effecting_node_ids = nodes
                .iter()
                .filter_map(|node| {
                    let tid: Uuid = node.get("type")?.as_str()?.parse().ok()?;
                    side_effecting_ids.contains(&tid).then(|| {
                        node.get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                            .to_string()
                    })
                })
                .collect();

            // Fuel-sizing inputs, captured BEFORE `template_rows` is consumed
            // into `template_schemas`: the module's shared default ceiling and
            // its capability world. Both are needed per node, and the node that
            // motivated this check had NO node-scoped override — its ceiling
            // came entirely from `modules.max_fuel`.
            let template_fuel: HashMap<Uuid, (Option<i64>, Option<String>)> = template_rows
                .iter()
                .map(|r| (r.id, (r.max_fuel, r.capability_world.clone())))
                .collect();

            // Retry-envelope inputs, captured from the same rows for the same
            // reason. A node that declares no `retry_count` still gets one at
            // dispatch — `default_max_retries_for_module(allowed_methods,
            // capability_world)` — so the envelope is NOT computable from the
            // graph alone. That is why this check lives here and not in the
            // pure `validate_graph_timeouts` walker.
            template_retry = template_rows
                .iter()
                .map(|r| {
                    (
                        r.id,
                        (r.allowed_methods.clone(), r.capability_world.clone()),
                    )
                })
                .collect();

            let template_schemas: HashMap<Uuid, (String, serde_json::Value, Vec<String>)> =
                template_rows
                    .into_iter()
                    .map(|r| {
                        let effective_secrets = installed_secrets
                            .get(&r.id)
                            .cloned()
                            .unwrap_or(r.allowed_secrets);
                        (r.id, (r.name, r.config_schema, effective_secrets))
                    })
                    .collect();

            // ── Fuel sizing vs the node's own configured maximum (Warning) ──
            //
            // Runs inside this block because it needs the template rows. See
            // the module-level rationale above `FUEL_PER_MAX_TOKEN` for why
            // this is a validation warning rather than a structural lint, and
            // for what it does and does not claim.
            let context_budget = talos_config::smart_memory_context_byte_budget() as u64;
            for node in &nodes {
                let node_label = node.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
                let node_data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
                // Both shapes: config keys are written flat under `data` by
                // `build_add_node_payload`, but nested `data.config` occurs in
                // imported and frontend-authored graphs.
                let cfg = node_data
                    .get("config")
                    .cloned()
                    .unwrap_or(node_data.clone());

                // Only a node that DECLARES a maximum output can be judged
                // against it. Absent `MAX_TOKENS` there is nothing to size
                // from and this check says nothing — deliberately, rather than
                // guessing at a default.
                let Some(max_tokens) = cfg.get("MAX_TOKENS").and_then(|v| v.as_u64()) else {
                    continue;
                };
                if max_tokens == 0 {
                    continue;
                }

                let tid: Option<Uuid> = node
                    .get("type")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok());
                let (module_fuel, world) = tid
                    .and_then(|t| template_fuel.get(&t))
                    .cloned()
                    .unwrap_or((None, None));

                // Mirrors `resolve_node_max_fuel`'s baseline:
                //   node-scoped `data.max_fuel` ?? `modules.max_fuel`.
                // The learned adaptive ceiling is NOT folded in, and that is
                // the point: adaptive is a runtime guard that needs five
                // samples in thirty days, so it is structurally unavailable to
                // a node being authored and to every weekly workflow. Sizing
                // against a number the node cannot rely on is how a budget
                // that never fit survives review.
                let effective = cfg
                    .get("max_fuel")
                    .and_then(|v| v.as_u64())
                    .or_else(|| module_fuel.filter(|f| *f > 0).map(|f| f as u64));
                // No ceiling knowable ⇒ no verdict. Saying nothing is correct
                // here; a warning would be about the module row, not the node.
                let Some(effective) = effective.filter(|f| *f > 0) else {
                    continue;
                };

                let injected = node_receives_actor_context(
                    world.as_deref(),
                    cfg.get("needs_memory").and_then(|v| v.as_bool()),
                );
                let budget = if injected { context_budget } else { 0 };
                let floor = required_fuel_floor(max_tokens, budget);
                if effective >= floor {
                    continue;
                }

                let injection_note = if injected {
                    format!(
                        " That figure includes {budget} bytes of __actor_context__ the engine \
                         injects into this node (its capability world is memory-eligible), which \
                         is NOT visible in module_executions.input_data — set needs_memory: false \
                         if the node does not consume memory."
                    )
                } else {
                    String::new()
                };
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    message: format!(
                        "Node '{node_label}' has max_fuel {effective} but its own configured \
                         MAX_TOKENS of {max_tokens} needs at least ~{floor}. The budget cannot \
                         pay for the output the node is configured to produce, so it is \
                         mis-sized before it has ever run — no amount of execution history \
                         fixes that, and adaptive fuel needs 5 runs in 30 days it may never \
                         get.{injection_note} Size it per docs/fuel-budget-sizing.md, and \
                         prefer a node-scoped data.max_fuel over modules.max_fuel, which is \
                         shared by every override-less consumer of that module."
                    ),
                    node_id: Some(node_label.to_string()),
                    category: "fuel-sizing".into(),
                });
            }

            // ── Retry envelope vs the workflow budget (Warning) ──────────────
            //
            // See the module-level rationale above `node_retry_envelope_secs`
            // for what this claims and what it deliberately does not.
            {
                // `budget == 0` disables the wall-clock cap entirely (per-node
                // timeouts become the only bound), so there is no container to
                // exceed. `budget` and `has_actor` are resolved once above and
                // shared with the observed-history check.
                if budget > 0 {
                    for node in &nodes {
                        let node_label =
                            node.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let Some(tid) = node
                            .get("type")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<Uuid>().ok())
                        else {
                            // System node (`system:*`) — its cost is the
                            // sub-workflow / judge it drives, not a dispatched
                            // module envelope. Saying nothing is correct.
                            continue;
                        };
                        let Some((methods, world)) = template_retry.get(&tid) else {
                            // Module row missing — already reported as a
                            // `missing_module` Error above; don't pile on.
                            continue;
                        };

                        let Some(overrun) = retry_envelope_overrun(
                            node,
                            budget,
                            has_actor,
                            methods,
                            world.as_deref(),
                            talos_workflow_engine_core::default_node_timeout_secs(),
                        ) else {
                            continue;
                        };

                        let RetryEnvelopeOverrun {
                            envelope_secs,
                            attempts,
                            per_attempt_secs,
                            resolved_retries,
                            retries_declared,
                        } = overrun;
                        let retry_note = if retries_declared {
                            format!("its declared retry_count of {resolved_retries}")
                        } else {
                            format!(
                                "the {resolved_retries} method-aware default retries its module \
                                 resolves to (it declares no retry_count)"
                            )
                        };
                        issues.push(ValidationIssue {
                            severity: ValidationSeverity::Warning,
                            message: format!(
                                "Node '{node_label}' has a retry envelope of ~{envelope_secs}s \
                                 ({attempts} attempts x {per_attempt_secs}s, plus backoff, from \
                                 {retry_note}) inside a workflow budget of {budget}s. At least \
                                 one configured attempt can never complete: the retry loop has no \
                                 view of the workflow deadline, so it starts the attempt anyway, \
                                 and when the budget expires the whole execution is dropped — \
                                 discarding every sibling node that had already finished. Lower \
                                 retry_count or raise execution_timeout_secs. Do NOT raise this \
                                 node's timeout_secs: that multiplies the envelope by the attempt \
                                 count and makes the failure arrive sooner."
                            ),
                            node_id: Some(node_label.to_string()),
                            category: "retry-envelope".into(),
                        });
                    }
                }
            }

            for node in &nodes {
                let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let node_data = node.get("data").cloned().unwrap_or(serde_json::json!({}));
                let node_config = node_data
                    .get("config")
                    .cloned()
                    .unwrap_or_else(|| node_data.clone());
                let tid: Option<Uuid> = node
                    .get("type")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse().ok());

                if let Some(tid) = tid {
                    if let Some((module_name, schema, allowed_secrets)) = template_schemas.get(&tid)
                    {
                        // Required config fields
                        let required: Vec<String> = schema
                            .get("required")
                            .and_then(|r| r.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();

                        let missing: Vec<String> = required
                            .iter()
                            .filter(|f| {
                                node_config
                                    .get(f.as_str())
                                    .map(|v| {
                                        v.is_null()
                                            || v.as_str().map(|s| s.is_empty()).unwrap_or(false)
                                    })
                                    .unwrap_or(true)
                            })
                            .cloned()
                            .collect();

                        if !missing.is_empty() {
                            issues.push(ValidationIssue {
                                severity: ValidationSeverity::Error,
                                message: format!(
                                    "Node '{}' (module: {}) missing required config: {}. \
                                     Set with update_node_config before triggering.",
                                    node_id,
                                    module_name,
                                    missing
                                        .iter()
                                        .map(|s| format!("'{}'", s))
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ),
                                node_id: Some(node_id.to_string()),
                                category: "config".into(),
                            });
                        }

                        // Vault path permission check
                        let has_wildcard = allowed_secrets.iter().any(|s| s == "*");
                        if let Some(cfg_obj) = node_config.as_object() {
                            for (field_key, field_val) in cfg_obj {
                                if let Some(val_str) = field_val.as_str() {
                                    if let Some(path) = val_str.strip_prefix("vault://") {
                                        if path.is_empty() {
                                            issues.push(ValidationIssue {
                                                severity: ValidationSeverity::Error,
                                                message: format!(
                                                    "Node '{}' (module: {}) config field '{}' has an empty \
                                                     vault:// reference. Must be 'vault://path/to/key'.",
                                                    node_id, module_name, field_key
                                                ),
                                                node_id: Some(node_id.to_string()),
                                                category: "vault".into(),
                                            });
                                            continue;
                                        }
                                        if path.starts_with("vault://") {
                                            issues.push(ValidationIssue {
                                                severity: ValidationSeverity::Error,
                                                message: format!(
                                                    "Node '{}' (module: {}) config field '{}' has a nested \
                                                     vault:// prefix (value: '{}'). Use a single prefix.",
                                                    node_id, module_name, field_key, val_str
                                                ),
                                                node_id: Some(node_id.to_string()),
                                                category: "vault".into(),
                                            });
                                            continue;
                                        }
                                        if !has_wildcard && !_vpp(allowed_secrets, path) {
                                            issues.push(ValidationIssue {
                                                severity: ValidationSeverity::Error,
                                                message: format!(
                                                    "Node '{}' (module: {}) config field '{}' references \
                                                     vault path '{}' which is blocked by the module's \
                                                     allowed_secrets [{}].",
                                                    node_id,
                                                    module_name,
                                                    field_key,
                                                    path,
                                                    if allowed_secrets.is_empty() {
                                                        "deny-all — no secrets granted".to_string()
                                                    } else {
                                                        allowed_secrets.join(", ")
                                                    }
                                                ),
                                                node_id: Some(node_id.to_string()),
                                                category: "vault".into(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // ── Observed failure history (Warning) ───────────────────────────
        //
        // Runs OUTSIDE the module block: a workflow made entirely of system
        // nodes still has an operational record, and the whole point of this
        // check is that `issues: []` must not be the answer for a workflow
        // that has been failing.
        //
        // See the module-level rationale above `HISTORY_WINDOW_DAYS` for what
        // this claims, what it deliberately does not, and — most importantly —
        // why every finding it produces is a Warning and never an Error.
        let window_days = history_window_days();
        // Hoisted out of the match so the disabled-retry check below can read
        // the SAME slice without a second query. Left EMPTY when the history
        // read failed or the window held nothing — that check must still run
        // (a node with no record has the same dead retry as one with 4,500
        // runs), it simply renders no observed clause.
        let mut observed_by_node: HashMap<Uuid, (ObservedNodeRecord, Option<String>)> =
            HashMap::new();
        let mut executions_scanned: i64 = 0;
        let history_coverage = match workflow_repo
            .node_run_history(workflow_id, user_id, window_days, HISTORY_MAX_EXECUTIONS)
            .await
        {
            Ok(history) => {
                // Map graph node id -> engine node id with the SAME function
                // the executor used to write the events. Deriving it locally
                // is how this join silently matches nothing, and zero matched
                // rows is indistinguishable from "no problems found" — i.e. it
                // would reproduce the exact bug this check exists to fix.
                observed_by_node = history
                    .nodes
                    .iter()
                    .map(|r| {
                        (
                            r.node_id,
                            (
                                ObservedNodeRecord {
                                    attempts: r.attempts,
                                    failures: r.failures,
                                    timeout_failures: r.timeout_failures,
                                },
                                r.latest_error.clone(),
                            ),
                        )
                    })
                    .collect();
                executions_scanned = history.executions_scanned;

                for node in &nodes {
                    let node_label = node.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let Some((observed, _)) = observed_by_node
                        .get(&talos_workflow_engine_core::engine_node_uuid(node_label))
                    else {
                        // Never ran inside the window. Silence is right: a node
                        // with no record is neither healthy nor unhealthy, and
                        // `history_coverage` on the result already tells the
                        // operator how much was examined.
                        continue;
                    };

                    // The static half applies only to module-dispatched nodes.
                    // A system node's cost is the sub-workflow / judge it
                    // drives, not a dispatched module envelope, so there is no
                    // per-attempt timeout or module retry default to report —
                    // exactly the reason `retry_envelope_overrun` skips them.
                    let headroom = node
                        .get("type")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<Uuid>().ok())
                        .and_then(|tid| template_retry.get(&tid))
                        .and_then(|(methods, world)| {
                            retry_headroom(
                                node,
                                budget,
                                has_actor,
                                methods,
                                world.as_deref(),
                                talos_workflow_engine_core::default_node_timeout_secs(),
                            )
                        });

                    let Some(finding) = chronic_node_failure(
                        observed,
                        history.executions_scanned,
                        history.window_days,
                        headroom,
                    ) else {
                        continue;
                    };

                    issues.push(ValidationIssue {
                        // WARNING, NEVER ERROR. `valid == false` gates
                        // `publish_version`; letting operational history flip
                        // it would make a workflow unpublishable because of a
                        // bad week — including when the thing being published
                        // is the fix. See the module-level note.
                        severity: ValidationSeverity::Warning,
                        message: describe_chronic_failure(&finding, node_label),
                        node_id: Some(node_label.to_string()),
                        category: "failure-history".into(),
                    });
                }

                if history.executions_scanned == 0 {
                    HistoryCoverage::Empty { window_days }
                } else {
                    HistoryCoverage::Observed {
                        executions: history.executions_scanned,
                        window_days,
                    }
                }
            }
            Err(e) => {
                // A failed read is NOT an empty history. Reporting it as
                // `Empty` would tell the operator "nothing has been observed"
                // when the truth is "we could not look" — the error-as-absence
                // shape (#661). `Unavailable` says so on the response.
                tracing::error!(
                    target: "talos_validation",
                    %workflow_id,
                    error = %e,
                    event_kind = "validation_history_read_failed",
                    "validate: execution-history read failed — history checks did not run"
                );
                HistoryCoverage::Unavailable
            }
        };

        // ── Explicitly disabled retry protection (Warning) ──────────────
        //
        // See the module-level rationale above `DisabledRetryProtection` for
        // what this claims, why it does NOT wait for an observed failure, and
        // why it never proposes a mutation.
        //
        // Runs OUTSIDE the history loop above on purpose: that loop `continue`s
        // on a node with no record, and a node that has never run has exactly
        // the same dead retry as one that has run 4,500 times. Observed history
        // decorates the finding here; it never gates it.
        //
        // Module-dispatched nodes only. A system node has no module row, so
        // there is no `allowed_methods` / `capability_world` to resolve a
        // default from — the same reason `retry_envelope_overrun` skips them.
        // `template_retry` was already fetched for the retry-envelope check, so
        // this adds no query and no per-node lookup beyond a hash hit.
        for node in &nodes {
            let node_label = node.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            let Some((methods, world)) = node
                .get("type")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Uuid>().ok())
                .and_then(|tid| template_retry.get(&tid))
            else {
                continue;
            };
            let Some(finding) = disabled_retry_protection(node, methods, world.as_deref()) else {
                continue;
            };
            let observed =
                observed_by_node.get(&talos_workflow_engine_core::engine_node_uuid(node_label));
            issues.push(ValidationIssue {
                // WARNING, NEVER ERROR — same reason as every finding above:
                // `valid == false` gates `publish_version`, and an explicit 0
                // is a legal configuration an operator may have chosen on
                // purpose. Blocking publication over it would be the platform
                // overruling the author.
                severity: ValidationSeverity::Warning,
                message: describe_disabled_retry_protection(
                    &finding,
                    node_label,
                    observed.map(|(o, _)| o),
                    latest_failure_is_transient(observed.and_then(|(_, e)| e.as_deref())),
                    executions_scanned,
                    window_days,
                ),
                node_id: Some(node_label.to_string()),
                category: "retry-disabled".into(),
            });
        }

        // ── Crash-recovery at-least-once advisory (Warning) ─────────────
        // Surfaces the durability contract to workflow authors: a controller
        // restart mid-execution re-dispatches in-flight nodes (at-least-once),
        // so side-effecting nodes can double-fire on a crash-recovery resume.
        if !side_effecting_node_ids.is_empty() {
            issues.push(ValidationIssue {
                severity: ValidationSeverity::Warning,
                message: format!(
                    "{} node(s) make external calls (declared allowed_hosts): {}. \
                     Crash-recovery resume is AT-LEAST-ONCE — if the controller \
                     restarts while one of these nodes is in flight, it is re-dispatched \
                     and re-runs. Make side-effecting nodes idempotent (e.g. an \
                     idempotency key / dedup guard) so a resume can't double-fire them \
                     (double charge / duplicate message).",
                    side_effecting_node_ids.len(),
                    side_effecting_node_ids.join(", ")
                ),
                node_id: None,
                category: "durability".into(),
            });
        }

        // ── LLM I/O enforcement-key advisory (Warning) ──────────────────
        // These config keys gate input sanitization (SANITIZE_FOR_LLM /
        // BLOCKED_PATTERNS) and output guardrails (OUTPUT_SCHEMA /
        // MAX_OUTPUT_CHARS_ENFORCED / MAX_OUTPUT_TOKENS_ENFORCED) inside
        // LLM-inference modules. Earlier compiled module bytes ignored
        // these keys silently; reinstalling the module recompiles against
        // the current template, which honours them.
        const LLM_ENFORCEMENT_KEYS: &[&str] = &[
            "SANITIZE_FOR_LLM",
            "BLOCKED_PATTERNS",
            "OUTPUT_SCHEMA",
            "MAX_OUTPUT_CHARS_ENFORCED",
            "MAX_OUTPUT_TOKENS_ENFORCED",
        ];
        for node in &nodes {
            let node_label = node.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            let node_config = node
                .get("config")
                .or_else(|| node.get("data").and_then(|d| d.get("config")));
            if let Some(cfg) = node_config {
                let keys_present: Vec<&str> = LLM_ENFORCEMENT_KEYS
                    .iter()
                    .copied()
                    .filter(|k| cfg.get(k).is_some())
                    .collect();
                if !keys_present.is_empty() {
                    issues.push(ValidationIssue {
                        severity: ValidationSeverity::Warning,
                        message: format!(
                            "Node '{}' configures LLM input/output enforcement key(s) {:?}. \
                             If the underlying module was compiled before these keys were honoured, \
                             they will be silently ignored at runtime — reinstall via \
                             reinstall_module_from_catalog (or recompile via hot_update_module) \
                             to pick up the current enforcement behaviour.",
                            node_label, keys_present
                        ),
                        node_id: Some(node_label.to_string()),
                        category: "llm-enforcement".into(),
                    });
                }
            }
        }

        // ── Reachability analysis (Warning) ──────────────────────────────
        let has_cycle = issues.iter().any(|i| i.category == "cycle");
        if !has_cycle && nodes.len() > 1 {
            let mut reachable: HashSet<petgraph::graph::NodeIndex> = HashSet::new();
            for (&idx, _) in graph_indices.iter().zip(node_ids.iter()) {
                if digraph
                    .edges_directed(idx, petgraph::Direction::Incoming)
                    .next()
                    .is_none()
                {
                    let mut dfs = petgraph::visit::Dfs::new(&digraph, idx);
                    while let Some(visited) = dfs.next(&digraph) {
                        reachable.insert(visited);
                    }
                }
            }
            let unreachable: Vec<&str> = graph_indices
                .iter()
                .zip(node_ids.iter())
                .filter_map(|(&idx, &id)| {
                    if !reachable.contains(&idx) {
                        Some(id)
                    } else {
                        None
                    }
                })
                .collect();
            if !unreachable.is_empty() {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    message: format!(
                        "Unreachable node(s) detected — will never execute: [{}].",
                        unreachable.join(", ")
                    ),
                    node_id: None,
                    category: "reachability".into(),
                });
            }
        }

        // ── Isolated-node detection (Warning) ─────────────────────────────
        // MCP-1211 (2026-05-18): the reachability check above treats any
        // node with no incoming edges as a DFS root, so a node with ZERO
        // edges (no incoming AND no outgoing) is "reachable from itself"
        // and slips through. In practice an isolated node runs every
        // execution but contributes nothing to the data flow — wasted
        // fuel with no operator signal. The daily-brief workflow has run
        // an isolated probe-loop node for 19 consecutive days, burning
        // ~46.5M fuel total with no warning surfaced. Flag isolated
        // non-trivial graphs (skip for single-node workflows, which are
        // legitimately edge-less).
        if nodes.len() > 1 {
            let isolated: Vec<&str> = graph_indices
                .iter()
                .zip(node_ids.iter())
                .filter_map(|(&idx, &id)| {
                    let no_in = digraph
                        .edges_directed(idx, petgraph::Direction::Incoming)
                        .next()
                        .is_none();
                    let no_out = digraph
                        .edges_directed(idx, petgraph::Direction::Outgoing)
                        .next()
                        .is_none();
                    if no_in && no_out {
                        Some(id)
                    } else {
                        None
                    }
                })
                .collect();
            if !isolated.is_empty() {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    message: format!(
                        "Isolated node(s) with no incoming or outgoing edges — they run on every \
                         execution but contribute nothing to the data flow: [{}]. \
                         Either connect them with add_edge or remove them.",
                        isolated.join(", ")
                    ),
                    node_id: None,
                    category: "isolated".into(),
                });
            }
        }

        // ── Loop-condition trivially-true detection (Warning) ─────────────
        // MCP-1211 (2026-05-18): a loop node with `condition: "true"`
        // (or any trivially-true Rhai expression) will always hit its
        // max_iterations safety cap. The execution still reports success,
        // so operators have no signal that the loop is misconfigured.
        // Conservative match: only flag literal-true forms — `"true"`,
        // `"1"`, `"!false"`, with optional whitespace and surrounding
        // parens. More complex Rhai expressions may evaluate truthy but
        // a static check would have false positives.
        for node in &nodes {
            let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let kind = node.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if kind != "loop" {
                continue;
            }
            let condition = node
                .get("data")
                .and_then(|d| d.get("condition"))
                .and_then(|c| c.as_str())
                .unwrap_or("");
            if is_trivially_true_condition(condition) {
                issues.push(ValidationIssue {
                    severity: ValidationSeverity::Warning,
                    message: format!(
                        "Loop node '{}' has a trivially-true condition ('{}'). The loop will run \
                         until max_iterations and terminate via the safety cap on every \
                         execution — almost certainly a misconfigured exit condition. Use a Rhai \
                         expression that references the body's output (e.g. \
                         `output.finished != true`).",
                        node_id, condition
                    ),
                    node_id: Some(node_id.to_string()),
                    category: "loop-condition".into(),
                });
            }
        }

        let valid = !issues
            .iter()
            .any(|i| i.severity == ValidationSeverity::Error);
        Ok(ValidationResult {
            valid,
            issues,
            history: history_coverage,
        })
    }

    /// Trigger-time input-schema check: fetch the workflow's declared
    /// `input_schema`, validate `trigger_input` against it, and return a
    /// typed [`InputSchemaCheck`] outcome the caller maps to JSON-RPC.
    ///
    /// `validate_only=true` requests dry-run mode — the result is returned
    /// even when validation fails, instead of short-circuiting. The caller
    /// (handler) shapes the dry-run JSON response from [`InputSchemaCheck::DryRun`].
    ///
    /// Database fetch errors degrade to `NoSchema` (logged at error level)
    /// — matching pre-extraction handler behavior, which intentionally
    /// allowed triggers to proceed when schema-fetch failed rather than
    /// rejecting all triggers on a transient DB hiccup.
    pub async fn check_trigger_input(
        workflow_repo: &WorkflowRepository,
        workflow_id: Uuid,
        user_id: Uuid,
        trigger_input: &serde_json::Value,
        validate_only: bool,
    ) -> InputSchemaCheck {
        let input_schema = match workflow_repo
            .get_workflow_input_schema(workflow_id, user_id)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("get_workflow_input_schema error: {}", e);
                None
            }
        };

        match (input_schema, validate_only) {
            (None, false) => InputSchemaCheck::NoSchema,
            (None, true) => InputSchemaCheck::DryRun {
                schema: None,
                errors: vec![],
            },
            (Some(schema), validate_only) => {
                let errors = validate_input_against_schema(&schema, trigger_input);
                if validate_only {
                    InputSchemaCheck::DryRun {
                        schema: Some(schema),
                        errors,
                    }
                } else if errors.is_empty() {
                    InputSchemaCheck::Valid
                } else {
                    InputSchemaCheck::Invalid(errors)
                }
            }
        }
    }
}

/// Trigger-time outcome of [`WorkflowValidationService::check_trigger_input`].
///
/// The variants split into "continue" (NoSchema, Valid), "block" (Invalid),
/// and "early-return-with-result" (DryRun) buckets — the handler picks a
/// JSON-RPC response shape per bucket.
#[derive(Debug)]
pub enum InputSchemaCheck {
    /// No `input_schema` is set on the workflow. Triggers proceed; any
    /// input is accepted.
    NoSchema,
    /// Schema is set and the trigger input passes. Caller continues to
    /// dispatch.
    Valid,
    /// Schema is set and the trigger input failed validation. Caller maps
    /// to MCP `-32602` with the joined error list.
    Invalid(Vec<String>),
    /// `validate_input=true` was supplied — return the validation result
    /// instead of dispatching. `schema` is `None` when no schema is set
    /// (the dry-run still reports valid=true with a "no schema" hint).
    DryRun {
        schema: Option<serde_json::Value>,
        errors: Vec<String>,
    },
}

/// Validate a JSON value against a JSON-Schema-flavored schema document.
///
/// Lifted from the inline `talos_mcp_handlers::workflows::validate_against_schema`
/// helper in May 2026; the move enables reuse from
/// [`WorkflowValidationService::check_trigger_input`] and any future
/// trigger-time validation surface (GraphQL, REST). Pure function — no
/// I/O, no shared state — recursion handles `anyOf` / `oneOf` / `allOf`
/// and nested-object descent.
///
/// Supports a deliberately-limited subset of JSON Schema:
/// * Top-level: `type`, `enum`, `minimum`/`maximum`, `minLength`/`maxLength`,
///   `pattern`, `anyOf`/`oneOf`/`allOf`, `required`, `additionalProperties: false`,
///   `properties`.
/// * Per-property: same constraint set as top-level, evaluated under the
///   property name for diagnostic prefixing.
///
/// Pattern compilation is bounded — patterns over 500 chars are rejected
/// before regex compilation, and the compiled-automaton size is capped at
/// 256 KB to prevent pathologically-complex patterns from stalling the
/// trigger path.
///
/// MCP-158 (2026-05-08): meta-validate a JSON Schema document at save
/// time so an operator-typo'd schema doesn't produce false-positive
/// `valid: true` responses at evaluation time.
///
/// `validate_input_against_schema` (below) silently passes through
/// unknown `type` values (line: `_ => true`) — which means a schema
/// like `{"type": "stirng"}` accepts every input. That's a footgun:
/// the operator stores broken validation, then `validate_workflow_input`
/// confidently green-lights any payload, and only the next workflow
/// failure reveals the typo. Catch it here at save time instead.
///
/// Recursively walks the schema's `properties`, `items`, `allOf`,
/// `anyOf`, `oneOf`, and `not` slots — same shape the runtime
/// evaluator handles. Returns a list of human-readable problems,
/// empty when the schema is well-formed enough to be safe.
/// MCP-204 helper: human-readable name for a JSON value's type.
/// Used in schema-validation error messages so the operator sees
/// "got string" / "got array" / "got null" rather than the raw
/// JSON dump.
fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// MCP-558: maximum schema/input nesting depth. The `walk` and
/// `validate_input_against_schema` recursive paths previously had no
/// cap, so a user-supplied schema (set via `set_workflow_input_schema`)
/// or trigger input could nest deeply enough to overflow the tokio
/// worker thread's 2 MB stack (~16-32k frames at 64-128 bytes each).
/// A 1 MB JSON body of `[[[[[...]]]]]` is ~500k levels, which crashes
/// the controller for ALL users, not just the request's sender —
/// auth doesn't bound the blast radius.
///
/// 128 is well above any legitimate schema (JSON Schema dialect
/// authors recommend ≤ 10 levels) and well below the stack-overflow
/// threshold. Picked to match serde_json's own built-in 128-deep
/// recursion limit at `from_slice`/`from_str` — the bound that already
/// governs `talos-memory`'s signed-RPC payloads (its
/// `MAX_CANONICAL_DEPTH` was deleted in #600 with the canonical-bytes
/// encoder; signatures now cover the exact wire bytes, so nothing
/// walks the tree) — so the related fail-closed depth limits agree.
const MAX_SCHEMA_DEPTH: usize = 128;

pub fn validate_schema_well_formed(schema: &serde_json::Value) -> Vec<String> {
    const VALID_TYPES: &[&str] = &[
        "null", "boolean", "object", "array", "number", "string", "integer",
    ];
    let mut errors = Vec::new();
    fn walk(node: &serde_json::Value, path: &str, errors: &mut Vec<String>, depth: usize) {
        const VALID_TYPES: &[&str] = &[
            "null", "boolean", "object", "array", "number", "string", "integer",
        ];
        if depth > MAX_SCHEMA_DEPTH {
            // MCP-558: short-circuit on excessive nesting. We push a
            // diagnostic so the operator can see what tripped the gate
            // (instead of a mysterious empty-errors result on what
            // should be an invalid schema).
            errors.push(format!(
                "Schema at '{}' exceeds maximum nesting depth of {} — refusing to walk further (possible DoS).",
                if path.is_empty() { "root" } else { path },
                MAX_SCHEMA_DEPTH
            ));
            return;
        }
        let obj = match node.as_object() {
            Some(o) => o,
            None => return,
        };
        if let Some(t) = obj.get("type") {
            // type can be a string OR an array of strings (JSON Schema allows
            // union types). Both shapes get validated against VALID_TYPES.
            match t {
                serde_json::Value::String(s) => {
                    if !VALID_TYPES.contains(&s.as_str()) {
                        errors.push(format!(
                            "Schema {} has unknown type '{}'. Valid types: {}.",
                            if path.is_empty() {
                                "root".to_string()
                            } else {
                                format!("at '{}'", path)
                            },
                            s,
                            VALID_TYPES.join(", ")
                        ));
                    }
                }
                serde_json::Value::Array(arr) => {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            if !VALID_TYPES.contains(&s) {
                                errors.push(format!(
                                    "Schema {} has unknown type '{}' in type-union. Valid types: {}.",
                                    if path.is_empty() { "root".to_string() } else { format!("at '{}'", path) },
                                    s,
                                    VALID_TYPES.join(", ")
                                ));
                            }
                        } else {
                            errors.push(format!(
                                "Schema {} type-union must contain only strings, got {}.",
                                if path.is_empty() {
                                    "root".to_string()
                                } else {
                                    format!("at '{}'", path)
                                },
                                v
                            ));
                        }
                    }
                }
                _ => {
                    errors.push(format!(
                        "Schema {} `type` must be a string or array of strings, got {}.",
                        if path.is_empty() {
                            "root".to_string()
                        } else {
                            format!("at '{}'", path)
                        },
                        t
                    ));
                }
            }
        }
        // MCP-204 (2026-05-08): validate each schema keyword's shape
        // explicitly. Pre-fix `obj.get(kw).and_then(|v| v.as_*())`
        // silently no-op'd when the keyword was present but the
        // wrong JSON type — e.g. `properties: "not-an-object"` or
        // `properties: ["not", "an", "object"]` would slip through
        // and produce confusing runtime behaviour.
        if let Some(props) = obj.get("properties") {
            match props.as_object() {
                Some(o) => {
                    for (k, sub) in o {
                        walk(sub, &format!("{}.properties.{}", path, k), errors, depth + 1);
                    }
                }
                None => errors.push(format!(
                    "Schema {} `properties` must be an object mapping field names to schemas, got {}.",
                    if path.is_empty() { "root".to_string() } else { format!("at '{}'", path) },
                    json_kind(props)
                )),
            }
        }
        if let Some(items) = obj.get("items") {
            // items may be a single schema OR an array of schemas (tuple form).
            match items {
                serde_json::Value::Object(_) => {
                    walk(items, &format!("{}.items", path), errors, depth + 1)
                }
                serde_json::Value::Array(arr) => {
                    for (i, sub) in arr.iter().enumerate() {
                        walk(sub, &format!("{}.items[{}]", path, i), errors, depth + 1);
                    }
                }
                _ => errors.push(format!(
                    "Schema {} `items` must be a schema object or array of schemas, got {}.",
                    if path.is_empty() {
                        "root".to_string()
                    } else {
                        format!("at '{}'", path)
                    },
                    json_kind(items)
                )),
            }
        }
        for kw in &["allOf", "anyOf", "oneOf"] {
            if let Some(v) = obj.get(*kw) {
                match v.as_array() {
                    Some(arr) => {
                        for (i, sub) in arr.iter().enumerate() {
                            walk(sub, &format!("{}.{}[{}]", path, kw, i), errors, depth + 1);
                        }
                    }
                    None => errors.push(format!(
                        "Schema {} `{}` must be an array of schemas, got {}.",
                        if path.is_empty() {
                            "root".to_string()
                        } else {
                            format!("at '{}'", path)
                        },
                        kw,
                        json_kind(v)
                    )),
                }
            }
        }
        if let Some(not) = obj.get("not") {
            if not.is_object() {
                walk(not, &format!("{}.not", path), errors, depth + 1);
            } else {
                errors.push(format!(
                    "Schema {} `not` must be a schema object, got {}.",
                    if path.is_empty() {
                        "root".to_string()
                    } else {
                        format!("at '{}'", path)
                    },
                    json_kind(not)
                ));
            }
        }
        if let Some(req) = obj.get("required") {
            if !req.is_array() {
                errors.push(format!(
                    "Schema {} `required` must be an array of strings.",
                    if path.is_empty() {
                        "root".to_string()
                    } else {
                        format!("at '{}'", path)
                    }
                ));
            } else if let Some(arr) = req.as_array() {
                for (i, v) in arr.iter().enumerate() {
                    if !v.is_string() {
                        errors.push(format!(
                            "Schema {} `required[{}]` must be a string, got {}.",
                            if path.is_empty() {
                                "root".to_string()
                            } else {
                                format!("at '{}'", path)
                            },
                            i,
                            v
                        ));
                    }
                }
            }
        }
    }
    walk(schema, "", &mut errors, 0);
    let _ = VALID_TYPES;
    errors
}

#[cfg(test)]
mod schema_meta_validation_tests {
    use super::validate_schema_well_formed;
    use serde_json::json;

    /// MCP-204 (2026-05-08): the validator silently no-op'd on
    /// `properties` / `items` / `allOf` / `anyOf` / `oneOf` / `not`
    /// when the keyword was present but the wrong JSON type, since
    /// the chained `as_*()` returned None and the if-let pattern
    /// matched nothing. Each shape now produces a specific error.
    #[test]
    fn rejects_properties_non_object() {
        for bad in [
            json!({"type": "object", "properties": "not-an-object"}),
            json!({"type": "object", "properties": ["not", "an", "object"]}),
            json!({"type": "object", "properties": null}),
            json!({"type": "object", "properties": 42}),
        ] {
            let errs = validate_schema_well_formed(&bad);
            assert!(
                errs.iter()
                    .any(|e| e.contains("`properties` must be an object")),
                "should reject {bad}; got {errs:?}"
            );
        }
    }

    #[test]
    fn rejects_items_wrong_type() {
        // items can be object OR array; null / string / number reject.
        for bad in [
            json!({"type": "array", "items": "string"}),
            json!({"type": "array", "items": null}),
            json!({"type": "array", "items": 5}),
        ] {
            let errs = validate_schema_well_formed(&bad);
            assert!(
                errs.iter()
                    .any(|e| e.contains("`items` must be a schema object or array")),
                "should reject {bad}; got {errs:?}"
            );
        }
    }

    #[test]
    fn accepts_items_array_form() {
        // Tuple form: items is an array of schemas.
        let schema = json!({
            "type": "array",
            "items": [{"type": "string"}, {"type": "integer"}]
        });
        assert!(validate_schema_well_formed(&schema).is_empty());
    }

    #[test]
    fn rejects_combinator_wrong_type() {
        for kw in ["allOf", "anyOf", "oneOf"] {
            let bad = json!({ kw: "not-array" });
            let errs = validate_schema_well_formed(&bad);
            assert!(
                errs.iter()
                    .any(|e| e.contains(&format!("`{kw}` must be an array"))),
                "should reject {bad}; got {errs:?}"
            );
        }
    }

    #[test]
    fn rejects_not_non_object() {
        let bad = json!({"not": "not-an-object"});
        let errs = validate_schema_well_formed(&bad);
        assert!(
            errs.iter()
                .any(|e| e.contains("`not` must be a schema object")),
            "got {errs:?}"
        );
    }

    #[test]
    fn accepts_canonical_schemas() {
        assert!(validate_schema_well_formed(&json!({})).is_empty());
        assert!(validate_schema_well_formed(&json!({"type": "object"})).is_empty());
        assert!(validate_schema_well_formed(&json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "integer"},
                "tags": {"type": "array", "items": {"type": "string"}}
            }
        }))
        .is_empty());
    }

    #[test]
    fn rejects_unknown_type_typo() {
        let errs = validate_schema_well_formed(&json!({"type": "stirng"}));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("stirng"));
    }

    #[test]
    fn rejects_nested_unknown_type() {
        let errs = validate_schema_well_formed(&json!({
            "type": "object",
            "properties": {
                "id": {"type": "uuid"}
            }
        }));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("uuid"));
        assert!(errs[0].contains("properties.id"));
    }

    #[test]
    fn accepts_type_union() {
        assert!(validate_schema_well_formed(&json!({
            "type": ["string", "null"]
        }))
        .is_empty());
    }

    #[test]
    fn rejects_type_union_typo() {
        let errs = validate_schema_well_formed(&json!({
            "type": ["string", "nul"]
        }));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("nul"));
    }

    #[test]
    fn rejects_required_non_array() {
        let errs = validate_schema_well_formed(&json!({
            "type": "object",
            "required": "name"
        }));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("required"));
    }
}

/// MCP-467: validate each element of an array against the schema's
/// `items` clause. JSON Schema admits two forms:
///   * `items: {schema}` — every element validated against `schema`.
///   * `items: [s0, s1, ...]` — tuple form; element at index `i`
///     validated against `s_i`. Elements past the end of the schema
///     list are unconstrained (per JSON Schema draft-07).
///
/// Pre-fix, the runtime validator silently dropped the `items` clause
/// — operators who defined `{"type": "array", "items": {"type":
/// "integer"}}` had their array contents bypass validation at trigger
/// time. The meta-validator (`validate_schema_well_formed`) correctly
/// walked `items` to check schema well-formedness, but the runtime
/// path never enforced the items contract, so payloads like
/// `["not", "ints"]` flowed through unblocked.
///
/// `index_label` prefixes errors with the property name when this is
/// called from per-property validation, or `""` when called from the
/// top-level array path. Errors are surfaced as `<prefix>[i]: <err>`
/// to give operators an actionable diagnostic.
fn validate_array_items(
    items_schema: &serde_json::Value,
    arr: &[serde_json::Value],
    index_label: &str,
    depth: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    let prefix = if index_label.is_empty() {
        String::new()
    } else {
        format!("Field '{}' ", index_label)
    };
    match items_schema {
        serde_json::Value::Object(_) => {
            for (i, item) in arr.iter().enumerate() {
                for err in validate_input_against_schema_depth(items_schema, item, depth + 1) {
                    out.push(format!("{}items[{}]: {}", prefix, i, err));
                }
            }
        }
        serde_json::Value::Array(tuple) => {
            for (i, item) in arr.iter().enumerate() {
                if let Some(sub) = tuple.get(i) {
                    for err in validate_input_against_schema_depth(sub, item, depth + 1) {
                        out.push(format!("{}items[{}]: {}", prefix, i, err));
                    }
                }
                // Elements past the tuple length are unconstrained.
            }
        }
        // Other shapes are caught by the meta-validator at save time;
        // be lenient here so a stored schema that slipped through (or
        // predates meta-validation) doesn't reject every input.
        _ => {}
    }
    out
}

/// Returns the (possibly-empty) list of human-readable error messages.
/// An empty Vec means the input passed.
pub fn validate_input_against_schema(
    schema: &serde_json::Value,
    input: &serde_json::Value,
) -> Vec<String> {
    // MCP-558: enter the depth-bounded path. The wrapper preserves the
    // existing public signature so every caller (handlers, MCP tools,
    // GraphQL) inherits the protection without explicit opt-in.
    validate_input_against_schema_depth(schema, input, 0)
}

fn validate_input_against_schema_depth(
    schema: &serde_json::Value,
    input: &serde_json::Value,
    depth: usize,
) -> Vec<String> {
    if depth > MAX_SCHEMA_DEPTH {
        // MCP-558: stop recursion before the tokio worker thread's 2 MB
        // stack runs out. anyOf/oneOf/allOf/items/properties are the
        // recursive surfaces; a deeply-nested schema OR a deeply-nested
        // INPUT (when paired with a permissive schema like
        // `{"type":"object"}`) both reach this gate. Surface a single
        // error string so the caller sees why validation cut short.
        return vec![format!(
            "Validation depth exceeded {} — refusing to recurse further (possible DoS).",
            MAX_SCHEMA_DEPTH
        )];
    }
    let mut errors = Vec::new();

    // ── Top-level type check ──────────────────────────────────────────────────
    // Must run BEFORE anyOf/oneOf/allOf so that sub-schemas like {type:"number"}
    // or {type:"string","enum":[...]} correctly reject mismatched values when called
    // recursively. Without this, a sub-schema with no `properties` block returns []
    // (no errors) for any input, making anyOf/oneOf/allOf effectively no-ops.
    if let Some(expected_type) = schema.get("type").and_then(|t| t.as_str()) {
        let type_ok = match expected_type {
            "string" => input.is_string(),
            "number" => input.is_number(),
            "integer" => input.is_i64() || input.is_u64(),
            "boolean" => input.is_boolean(),
            "array" => input.is_array(),
            "object" => input.is_object(),
            "null" => input.is_null(),
            _ => true,
        };
        if !type_ok {
            let actual = match input {
                serde_json::Value::Null => "null",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::Object(_) => "object",
            };
            // Early return: a type mismatch makes all further constraint checks meaningless.
            // MCP-1032: schema-author-supplied `expected_type` capped; `actual` is from
            // a fixed 6-string allowlist (null/boolean/number/string/array/object).
            errors.push(format!(
                "Expected type '{}' but got '{}'",
                talos_text_util::bounded_preview(expected_type, 64),
                actual
            ));
            return errors;
        }
    }

    // ── Top-level `items` (array element) validation — MCP-467 ──────────
    if let (Some(items_schema), Some(arr)) = (schema.get("items"), input.as_array()) {
        errors.extend(validate_array_items(items_schema, arr, "", depth));
    }

    // ── Top-level enum check ──────────────────────────────────────────────────
    if let Some(enum_values) = schema.get("enum").and_then(|e| e.as_array()) {
        if !enum_values.contains(input) {
            let valid_values: Vec<String> = enum_values
                .iter()
                .map(|v| match v.as_str() {
                    Some(s) => format!("\"{}\"", s),
                    None => v.to_string(),
                })
                .collect();
            errors.push(format!(
                "Value must be one of [{}] but got {}",
                valid_values.join(", "),
                input
            ));
        }
    }

    // ── Top-level numeric range checks ────────────────────────────────────────
    if let Some(n) = input.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(|v| v.as_f64()) {
            if n < min {
                errors.push(format!("Value must be >= {}", min));
            }
        }
        if let Some(max) = schema.get("maximum").and_then(|v| v.as_f64()) {
            if n > max {
                errors.push(format!("Value must be <= {}", max));
            }
        }
    }

    // ── Top-level string constraint checks ────────────────────────────────────
    if let Some(s) = input.as_str() {
        let len = s.chars().count();
        if let Some(min_len) = schema.get("minLength").and_then(|v| v.as_u64()) {
            if len < min_len as usize {
                errors.push(format!(
                    "Value must be at least {} character(s) long",
                    min_len
                ));
            }
        }
        if let Some(max_len) = schema.get("maxLength").and_then(|v| v.as_u64()) {
            if len > max_len as usize {
                errors.push(format!(
                    "Value must be at most {} character(s) long",
                    max_len
                ));
            }
        }
        if let Some(pat) = schema.get("pattern").and_then(|p| p.as_str()) {
            if pat.len() > 500 {
                errors.push(
                    "Regex pattern in schema exceeds maximum length of 500 characters".into(),
                );
            } else {
                // Bound the compiled automaton size (default 10 MB → capped at 256 KB)
                // to prevent slow compilation of pathologically complex patterns.
                match regex::RegexBuilder::new(pat).size_limit(256 * 1024).build() {
                    Ok(re) if !re.is_match(s) => {
                        errors.push(format!("Value does not match pattern {:?}", pat));
                    }
                    Err(_) => {
                        errors.push(format!("Invalid or too-complex regex pattern {:?}", pat));
                    }
                    _ => {}
                }
            }
        }
    }

    // ── anyOf ─────────────────────────────────────────────────────────────────
    if let Some(any_of) = schema.get("anyOf").and_then(|v| v.as_array()) {
        if !any_of
            .iter()
            .any(|s| validate_input_against_schema_depth(s, input, depth + 1).is_empty())
        {
            errors.push("Value does not match any of the expected schemas (anyOf)".into());
        }
    }

    // ── oneOf ─────────────────────────────────────────────────────────────────
    if let Some(one_of) = schema.get("oneOf").and_then(|v| v.as_array()) {
        let n = one_of
            .iter()
            .filter(|s| validate_input_against_schema_depth(s, input, depth + 1).is_empty())
            .count();
        if n != 1 {
            errors.push(format!(
                "Value must match exactly one schema (oneOf) but matched {}",
                n
            ));
        }
    }

    // ── allOf ─────────────────────────────────────────────────────────────────
    if let Some(all_of) = schema.get("allOf").and_then(|v| v.as_array()) {
        for (i, sub) in all_of.iter().enumerate() {
            for err in validate_input_against_schema_depth(sub, input, depth + 1) {
                errors.push(format!("allOf[{}]: {}", i, err));
            }
        }
    }

    // Check required fields
    if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
        for req_field in required {
            let field = match req_field.as_str() {
                Some(f) => f,
                None => continue,
            };
            if input.get(field).is_none() {
                errors.push(format!("Missing required field: '{}'", field));
            }
        }
    }

    // ── additionalProperties: false ───────────────────────────────────────
    if schema.get("additionalProperties").and_then(|v| v.as_bool()) == Some(false) {
        if let (Some(props), Some(obj)) = (
            schema.get("properties").and_then(|p| p.as_object()),
            input.as_object(),
        ) {
            for key in obj.keys() {
                if !props.contains_key(key.as_str()) {
                    errors.push(format!(
                        "Field '{}' is not allowed (additionalProperties: false)",
                        key
                    ));
                }
            }
        }
    }

    // Check per-property constraints when both schema and input are objects
    if let (Some(props), Some(input_obj)) = (
        schema.get("properties").and_then(|p| p.as_object()),
        input.as_object(),
    ) {
        for (field, field_schema) in props {
            let Some(input_val) = input_obj.get(field) else {
                continue;
            };

            // ── type check ────────────────────────────────────────────────
            if let Some(expected_type) = field_schema.get("type").and_then(|t| t.as_str()) {
                let type_ok = match expected_type {
                    "string" => input_val.is_string(),
                    "number" => input_val.is_number(),
                    "integer" => input_val.is_i64() || input_val.is_u64(),
                    "boolean" => input_val.is_boolean(),
                    "array" => input_val.is_array(),
                    "object" => input_val.is_object(),
                    "null" => input_val.is_null(),
                    _ => true,
                };
                if !type_ok {
                    let actual = match input_val {
                        serde_json::Value::Null => "null",
                        serde_json::Value::Bool(_) => "boolean",
                        serde_json::Value::Number(_) => "number",
                        serde_json::Value::String(_) => "string",
                        serde_json::Value::Array(_) => "array",
                        serde_json::Value::Object(_) => "object",
                    };
                    // MCP-1032: schema-author-supplied `field` and `expected_type` capped;
                    // `actual` is from a fixed 6-string allowlist.
                    errors.push(format!(
                        "Field '{}' must be of type '{}' but got '{}'",
                        talos_text_util::bounded_preview(field, 64),
                        talos_text_util::bounded_preview(expected_type, 64),
                        actual
                    ));
                }
            }

            // ── enum check ────────────────────────────────────────────────
            if let Some(enum_values) = field_schema.get("enum").and_then(|e| e.as_array()) {
                if !enum_values.contains(input_val) {
                    let valid_values: Vec<String> = enum_values
                        .iter()
                        .map(|v| match v.as_str() {
                            Some(s) => format!("\"{}\"", s),
                            None => v.to_string(),
                        })
                        .collect();
                    errors.push(format!(
                        "Field '{}' must be one of [{}] but got {}",
                        field,
                        valid_values.join(", "),
                        input_val
                    ));
                }
            }

            // ── numeric range checks ──────────────────────────────────────
            if let Some(n) = input_val.as_f64() {
                if let Some(min) = field_schema.get("minimum").and_then(|v| v.as_f64()) {
                    if n < min {
                        errors.push(format!("Field '{}' must be >= {}", field, min));
                    }
                }
                if let Some(max) = field_schema.get("maximum").and_then(|v| v.as_f64()) {
                    if n > max {
                        errors.push(format!("Field '{}' must be <= {}", field, max));
                    }
                }
            }

            // ── string length + pattern checks ────────────────────────────
            if let Some(s) = input_val.as_str() {
                let len = s.chars().count();
                if let Some(min_len) = field_schema.get("minLength").and_then(|v| v.as_u64()) {
                    if len < min_len as usize {
                        errors.push(format!(
                            "Field '{}' must be at least {} character(s) long",
                            field, min_len
                        ));
                    }
                }
                if let Some(max_len) = field_schema.get("maxLength").and_then(|v| v.as_u64()) {
                    if len > max_len as usize {
                        errors.push(format!(
                            "Field '{}' must be at most {} character(s) long",
                            field, max_len
                        ));
                    }
                }

                // ── pattern ───────────────────────────────────────────────
                if let Some(pat) = field_schema.get("pattern").and_then(|p| p.as_str()) {
                    if pat.len() > 500 {
                        errors.push(format!(
                            "Field '{}' has a regex pattern exceeding maximum length of 500 characters",
                            field
                        ));
                    } else {
                        // Bound the compiled automaton size to prevent slow compilation
                        // of pathologically complex patterns.
                        match regex::RegexBuilder::new(pat).size_limit(256 * 1024).build() {
                            Ok(re) if !re.is_match(s) => {
                                errors.push(format!(
                                    "Field '{}' does not match pattern {:?}",
                                    field, pat
                                ));
                            }
                            Err(_) => {
                                errors.push(format!(
                                    "Field '{}' has invalid or too-complex regex pattern {:?}",
                                    field, pat
                                ));
                            }
                            _ => {}
                        }
                    }
                }
            }

            // ── anyOf / oneOf / allOf in field_schema ────────────────────
            // Must be evaluated explicitly here for all value types. The
            // nested-object block below only recurses when input_val.is_object();
            // without this block, combiner schemas on scalars (strings, numbers,
            // booleans) would silently pass regardless of sub-schema constraints.
            if let Some(any_of) = field_schema.get("anyOf").and_then(|v| v.as_array()) {
                if !any_of.iter().any(|s| {
                    validate_input_against_schema_depth(s, input_val, depth + 1).is_empty()
                }) {
                    errors.push(format!(
                        "Field '{}' does not match any of the expected schemas (anyOf)",
                        field
                    ));
                }
            }
            if let Some(one_of) = field_schema.get("oneOf").and_then(|v| v.as_array()) {
                let n = one_of
                    .iter()
                    .filter(|s| {
                        validate_input_against_schema_depth(s, input_val, depth + 1).is_empty()
                    })
                    .count();
                if n != 1 {
                    errors.push(format!(
                        "Field '{}' must match exactly one schema (oneOf) but matched {}",
                        field, n
                    ));
                }
            }
            if let Some(all_of) = field_schema.get("allOf").and_then(|v| v.as_array()) {
                for (i, sub) in all_of.iter().enumerate() {
                    for err in validate_input_against_schema_depth(sub, input_val, depth + 1) {
                        errors.push(format!("Field '{}' allOf[{}]: {}", field, i, err));
                    }
                }
            }

            // ── per-property `items` (array element) — MCP-467 ────────────
            if let (Some(items_schema), Some(arr)) =
                (field_schema.get("items"), input_val.as_array())
            {
                errors.extend(validate_array_items(items_schema, arr, field, depth));
            }

            // ── nested object ─────────────────────────────────────────────
            if input_val.is_object()
                && (field_schema.get("properties").is_some()
                    || field_schema.get("required").is_some())
            {
                for err in validate_input_against_schema_depth(field_schema, input_val, depth + 1) {
                    errors.push(format!("{}.{}", field, err));
                }
            }
        }
    }

    errors
}

/// Pure: numeric-aware JSON equality. Treats `5` and `5.0` as equal so
/// assertion checks pass against JSON serializers that emit
/// whole-number floats. Falls back to standard `PartialEq` for
/// non-numeric values.
pub fn json_values_equal_numeric_aware(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    match (a, b) {
        (serde_json::Value::Number(na), serde_json::Value::Number(nb)) => {
            na.as_f64() == nb.as_f64()
        }
        _ => a == b,
    }
}

/// Pure: look up a key in a workflow test-output value. Searches the
/// top level first; if missing, searches one level deep across the
/// object's values (the per-node-output map). Used by
/// `assert_output_contains` so callers can match either the top-level
/// shape or any single node's output without naming it.
pub fn lookup_test_output_key<'a>(
    output: &'a serde_json::Value,
    key: &str,
) -> Option<&'a serde_json::Value> {
    if let Some(v) = output.get(key) {
        return Some(v);
    }
    output
        .as_object()
        .and_then(|obj| obj.values().find_map(|v| v.get(key)))
}

/// Pure: build the per-assertion JSON list + overall pass/fail flag for
/// a `test_workflow` invocation. Composes the three currently-supported
/// assertion kinds — exact-status match, max-duration cap,
/// output-contains key/value matching — into the array shape MCP clients
/// expect. Returns `(assertions, all_passed)`; assertions are ordered
/// status → max_duration → output_contains.* (alphabetical by key).
///
/// This is the canonical implementation; `handle_test_workflow` calls
/// this directly so the assertion logic is unit-tested in isolation
/// rather than embedded in the handler.
pub fn build_test_assertions(
    actual_status: &str,
    expected_status: &str,
    duration_ms: u64,
    assert_max_duration_ms: Option<u64>,
    output_json: &serde_json::Value,
    assert_output_contains: Option<&serde_json::Map<String, serde_json::Value>>,
) -> (Vec<serde_json::Value>, bool) {
    let mut assertions = Vec::new();
    let mut all_passed = true;

    let status_passed = actual_status == expected_status;
    if !status_passed {
        all_passed = false;
    }
    assertions.push(serde_json::json!({
        "name": "status",
        "expected": expected_status,
        "actual": actual_status,
        "passed": status_passed,
    }));

    if let Some(max_ms) = assert_max_duration_ms {
        let duration_passed = duration_ms <= max_ms;
        if !duration_passed {
            all_passed = false;
        }
        assertions.push(serde_json::json!({
            "name": "max_duration_ms",
            "expected": format!("<= {}", max_ms),
            "actual": duration_ms,
            "passed": duration_passed,
        }));
    }

    if let Some(expected_kv) = assert_output_contains {
        for (key, expected_val) in expected_kv {
            let actual_val = lookup_test_output_key(output_json, key);
            let contains_passed = actual_val
                .map(|v| json_values_equal_numeric_aware(v, expected_val))
                .unwrap_or(false);
            if !contains_passed {
                all_passed = false;
            }
            assertions.push(serde_json::json!({
                "name": format!("output_contains.{}", key),
                "expected": expected_val,
                "actual": actual_val.unwrap_or(&serde_json::Value::Null),
                "passed": contains_passed,
            }));
        }
    }

    (assertions, all_passed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── is_trivially_true_condition (MCP-1211) ──────────────────────────
    #[test]
    fn trivially_true_matches_literal_true() {
        assert!(is_trivially_true_condition("true"));
        assert!(is_trivially_true_condition("TRUE"));
        assert!(is_trivially_true_condition("True"));
        assert!(is_trivially_true_condition("  true  "));
    }

    #[test]
    fn trivially_true_matches_literal_one() {
        assert!(is_trivially_true_condition("1"));
        assert!(is_trivially_true_condition(" 1 "));
    }

    #[test]
    fn trivially_true_matches_not_false() {
        assert!(is_trivially_true_condition("!false"));
        assert!(is_trivially_true_condition("!FALSE"));
        assert!(is_trivially_true_condition(" !false "));
    }

    #[test]
    fn trivially_true_strips_balanced_parens() {
        assert!(is_trivially_true_condition("(true)"));
        assert!(is_trivially_true_condition("((true))"));
        assert!(is_trivially_true_condition("( ( true ) )"));
    }

    #[test]
    fn trivially_true_rejects_dynamic_expressions() {
        assert!(!is_trivially_true_condition("output.finished != true"));
        assert!(!is_trivially_true_condition("x > 0"));
        assert!(!is_trivially_true_condition("output.iterations < 10"));
        assert!(!is_trivially_true_condition(""));
        assert!(!is_trivially_true_condition("false"));
        assert!(!is_trivially_true_condition("0"));
        assert!(!is_trivially_true_condition("!true"));
    }

    #[test]
    fn trivially_true_rejects_unbalanced_outer_parens() {
        // `(true) || (false)` has a leading `(` and trailing `)` but they
        // don't enclose the whole expression — the outer-paren strip must
        // NOT collapse this to `true) || (false`.
        assert!(!is_trivially_true_condition("(true) || (false)"));
        assert!(!is_trivially_true_condition("(true) || x"));
    }

    #[test]
    fn validates_top_level_type_match() {
        let schema = json!({"type": "string"});
        assert!(validate_input_against_schema(&schema, &json!("hi")).is_empty());
        let errs = validate_input_against_schema(&schema, &json!(42));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("Expected type 'string' but got 'number'"));
    }

    #[test]
    fn validates_required_fields() {
        let schema = json!({"type": "object", "required": ["name", "id"]});
        let input = json!({"name": "alice"});
        let errs = validate_input_against_schema(&schema, &input);
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("Missing required field: 'id'"));
    }

    #[test]
    fn validates_per_property_type_with_field_prefix() {
        let schema = json!({
            "type": "object",
            "properties": { "age": {"type": "integer"} }
        });
        let errs = validate_input_against_schema(&schema, &json!({"age": "old"}));
        assert_eq!(errs.len(), 1);
        assert!(errs[0].contains("Field 'age'"));
        assert!(errs[0].contains("integer"));
        assert!(errs[0].contains("string"));
    }

    #[test]
    fn anyof_with_top_level_type_check_rejects_mismatched_scalar() {
        // Regression guard: pre-fix, sub-schemas without `properties` returned
        // [] for any input, making anyOf no-ops on scalars.
        let schema = json!({ "anyOf": [{"type": "string"}, {"type": "number"}] });
        let errs = validate_input_against_schema(&schema, &json!(true));
        assert!(
            !errs.is_empty(),
            "anyOf must reject boolean against [string,number]"
        );
    }

    #[test]
    fn additional_properties_false_rejects_unknown_keys() {
        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": { "name": {"type": "string"} }
        });
        let errs = validate_input_against_schema(&schema, &json!({"name": "a", "extra": 1}));
        assert!(errs.iter().any(|e| e.contains("'extra' is not allowed")));
    }

    #[test]
    fn pattern_max_length_rejected_before_compile() {
        // Defense-in-depth: 600-char regex is rejected without compilation
        // — protects against pathologically-complex patterns stalling triggers.
        let big_pat = "a".repeat(600);
        let schema = json!({"type": "string", "pattern": big_pat});
        let errs = validate_input_against_schema(&schema, &json!("hello"));
        assert!(errs.iter().any(|e| e.contains("exceeds maximum length")));
    }

    // MCP-467: `items` validation at runtime. Pre-fix, the runtime
    // validator silently dropped the items clause — a schema like
    // `{"type": "array", "items": {"type": "integer"}}` accepted
    // `["not", "ints"]` as valid input. Operators had a false sense
    // of trigger-time input validation. All four tests below would
    // produce `errs.is_empty() == true` before the fix and reject
    // correctly after.

    #[test]
    fn items_validates_top_level_single_schema() {
        let schema = json!({"type": "array", "items": {"type": "integer"}});
        let errs = validate_input_against_schema(&schema, &json!(["a", "b"]));
        assert!(
            !errs.is_empty(),
            "items {{integer}} must reject array of strings; got no errors"
        );
        assert!(
            errs.iter().any(|e| e.contains("items[0]")),
            "expected index in error path: {:?}",
            errs
        );
    }

    #[test]
    fn items_accepts_matching_array() {
        let schema = json!({"type": "array", "items": {"type": "integer"}});
        let errs = validate_input_against_schema(&schema, &json!([1, 2, 3]));
        assert!(
            errs.is_empty(),
            "items {{integer}} must accept [1,2,3]: {:?}",
            errs
        );
    }

    #[test]
    fn items_validates_per_property() {
        let schema = json!({
            "type": "object",
            "properties": {
                "tags": {"type": "array", "items": {"type": "string"}}
            }
        });
        let errs = validate_input_against_schema(&schema, &json!({"tags": [1, 2]}));
        assert!(!errs.is_empty(), "tags items {{string}} must reject [1,2]");
        assert!(
            errs.iter()
                .any(|e| e.contains("Field 'tags'") && e.contains("items[0]")),
            "expected field+index prefix in error path: {:?}",
            errs
        );
    }

    #[test]
    fn items_validates_tuple_form() {
        // JSON Schema draft-07 tuple form: items[i] validated against
        // schema[i]; elements past schema list are unconstrained.
        let schema = json!({
            "type": "array",
            "items": [{"type": "string"}, {"type": "integer"}]
        });
        // Valid: [str, int, anything-extra]
        let errs =
            validate_input_against_schema(&schema, &json!(["a", 5, "extra-elements-allowed"]));
        assert!(
            errs.is_empty(),
            "tuple-extra should be unconstrained: {:?}",
            errs
        );
        // Invalid: position 0 must be string, got int
        let errs = validate_input_against_schema(&schema, &json!([5, 5]));
        assert!(errs.iter().any(|e| e.contains("items[0]")), "{:?}", errs);
    }

    #[test]
    fn nested_object_errors_are_dotted() {
        let schema = json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": { "age": {"type": "integer"} }
                }
            }
        });
        let errs = validate_input_against_schema(&schema, &json!({"user": {"age": "old"}}));
        assert!(
            errs.iter().any(|e| e.starts_with("user.")),
            "nested errs should be dotted: {:?}",
            errs
        );
    }

    // -- json_values_equal_numeric_aware --

    #[test]
    fn numeric_eq_int_vs_whole_float() {
        assert!(json_values_equal_numeric_aware(&json!(5), &json!(5.0)));
        assert!(json_values_equal_numeric_aware(&json!(5.0), &json!(5)));
    }

    #[test]
    fn numeric_eq_distinguishes_unequal_numbers() {
        assert!(!json_values_equal_numeric_aware(&json!(5), &json!(6)));
        assert!(!json_values_equal_numeric_aware(&json!(5.0), &json!(5.1)));
    }

    #[test]
    fn numeric_eq_falls_back_for_non_numbers() {
        assert!(json_values_equal_numeric_aware(
            &json!("foo"),
            &json!("foo")
        ));
        assert!(!json_values_equal_numeric_aware(
            &json!("foo"),
            &json!("bar")
        ));
        assert!(json_values_equal_numeric_aware(&json!(true), &json!(true)));
        assert!(json_values_equal_numeric_aware(
            &json!({"a": 1}),
            &json!({"a": 1})
        ));
    }

    #[test]
    fn numeric_eq_number_vs_string_unequal() {
        // No coercion across types — "5" is not 5.
        assert!(!json_values_equal_numeric_aware(&json!(5), &json!("5")));
    }

    // -- lookup_test_output_key --

    #[test]
    fn lookup_finds_top_level_key() {
        let v = json!({"status": "ok", "count": 3});
        assert_eq!(lookup_test_output_key(&v, "status"), Some(&json!("ok")));
    }

    #[test]
    fn lookup_descends_one_level_when_top_misses() {
        let v = json!({
            "node_a": {"status": "ok"},
            "node_b": {"count": 7},
        });
        assert_eq!(lookup_test_output_key(&v, "count"), Some(&json!(7)));
    }

    #[test]
    fn lookup_returns_none_when_missing() {
        let v = json!({"node_a": {"status": "ok"}});
        assert!(lookup_test_output_key(&v, "missing").is_none());
    }

    #[test]
    fn lookup_top_level_shadows_nested() {
        // Top-level wins, even if a nested entry has the same key.
        let v = json!({
            "result": "top",
            "node_a": {"result": "nested"},
        });
        assert_eq!(lookup_test_output_key(&v, "result"), Some(&json!("top")));
    }

    // ─── build_test_assertions ───

    #[test]
    fn assertions_status_only_passes_when_status_matches() {
        let (asserts, all_passed) =
            build_test_assertions("completed", "completed", 100, None, &json!({}), None);
        assert!(all_passed);
        assert_eq!(asserts.len(), 1);
        assert_eq!(asserts[0]["name"], "status");
        assert_eq!(asserts[0]["passed"], true);
        assert_eq!(asserts[0]["expected"], "completed");
        assert_eq!(asserts[0]["actual"], "completed");
    }

    #[test]
    fn assertions_status_mismatch_marks_all_failed() {
        let (asserts, all_passed) =
            build_test_assertions("failed", "completed", 100, None, &json!({}), None);
        assert!(!all_passed);
        assert_eq!(asserts[0]["passed"], false);
    }

    #[test]
    fn assertions_max_duration_passes_within_cap() {
        let (asserts, all_passed) =
            build_test_assertions("completed", "completed", 50, Some(100), &json!({}), None);
        assert!(all_passed);
        assert_eq!(asserts.len(), 2);
        assert_eq!(asserts[1]["name"], "max_duration_ms");
        assert_eq!(asserts[1]["passed"], true);
        assert_eq!(asserts[1]["expected"], "<= 100");
        assert_eq!(asserts[1]["actual"], 50);
    }

    #[test]
    fn assertions_max_duration_fails_when_over() {
        let (asserts, all_passed) =
            build_test_assertions("completed", "completed", 200, Some(100), &json!({}), None);
        assert!(!all_passed);
        assert_eq!(asserts[1]["passed"], false);
    }

    #[test]
    fn assertions_max_duration_omitted_when_no_cap_provided() {
        let (asserts, _) =
            build_test_assertions("completed", "completed", 999_999, None, &json!({}), None);
        assert_eq!(asserts.len(), 1); // only status
    }

    #[test]
    fn assertions_output_contains_passes_top_level_key() {
        let output = json!({"status": "ok", "count": 7});
        let mut expected = serde_json::Map::new();
        expected.insert("status".to_string(), json!("ok"));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(all_passed);
        assert_eq!(asserts.len(), 2); // status + output_contains.status
        assert_eq!(asserts[1]["name"], "output_contains.status");
        assert_eq!(asserts[1]["passed"], true);
    }

    #[test]
    fn assertions_output_contains_finds_nested_key() {
        let output = json!({"node_a": {"count": 5}});
        let mut expected = serde_json::Map::new();
        expected.insert("count".to_string(), json!(5));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(all_passed);
        assert_eq!(asserts[1]["passed"], true);
        assert_eq!(asserts[1]["actual"], 5);
    }

    #[test]
    fn assertions_output_contains_numeric_aware_equality() {
        // 5 vs 5.0 must compare equal.
        let output = json!({"count": 5});
        let mut expected = serde_json::Map::new();
        expected.insert("count".to_string(), json!(5.0));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(all_passed);
        assert_eq!(asserts[1]["passed"], true);
    }

    #[test]
    fn assertions_output_contains_missing_key_fails_with_null_actual() {
        let output = json!({"status": "ok"});
        let mut expected = serde_json::Map::new();
        expected.insert("missing".to_string(), json!("anything"));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(!all_passed);
        assert_eq!(asserts[1]["passed"], false);
        assert_eq!(asserts[1]["actual"], serde_json::Value::Null);
    }

    #[test]
    fn assertions_output_contains_value_mismatch_fails() {
        let output = json!({"status": "ok"});
        let mut expected = serde_json::Map::new();
        expected.insert("status".to_string(), json!("error"));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            100,
            None,
            &output,
            Some(&expected),
        );
        assert!(!all_passed);
        assert_eq!(asserts[1]["passed"], false);
        assert_eq!(asserts[1]["expected"], "error");
        assert_eq!(asserts[1]["actual"], "ok");
    }

    #[test]
    fn assertions_compose_all_three_kinds() {
        let output = json!({"status": "ok"});
        let mut expected = serde_json::Map::new();
        expected.insert("status".to_string(), json!("ok"));
        let (asserts, all_passed) = build_test_assertions(
            "completed",
            "completed",
            50,
            Some(100),
            &output,
            Some(&expected),
        );
        assert!(all_passed);
        assert_eq!(asserts.len(), 3);
        assert_eq!(asserts[0]["name"], "status");
        assert_eq!(asserts[1]["name"], "max_duration_ms");
        assert_eq!(asserts[2]["name"], "output_contains.status");
    }

    // MCP-558: tripwire — confirm the recursive validators bail at
    // MAX_SCHEMA_DEPTH instead of stack-overflowing on a deeply
    // nested input. Previously a malicious user could submit a
    // `[[[[[...]]]]]` body (~500k levels per 1 MB axum body limit)
    // and crash the controller for ALL users.
    #[test]
    fn validate_input_against_schema_bails_on_deep_nesting() {
        // Schema with no `items` constraint but with allOf wrapping
        // itself N times: each allOf step recurses through
        // validate_input_against_schema_depth.
        let mut schema = json!({"type": "array"});
        for _ in 0..(super::MAX_SCHEMA_DEPTH + 10) {
            schema = json!({ "allOf": [schema] });
        }
        let errors = validate_input_against_schema(&schema, &json!([]));
        // We get exactly one "Validation depth exceeded" message at the
        // first level beyond MAX_SCHEMA_DEPTH; the recursive walk stops
        // and returns up through each allOf wrapper.
        assert!(
            errors.iter().any(|e| e.contains("depth exceeded")),
            "expected depth-bailout error, got {:?}",
            errors
        );
    }

    #[test]
    fn validate_schema_well_formed_bails_on_deep_nesting() {
        // Schema with N levels of nested `properties.x` chain.
        let mut schema = json!({ "type": "string" });
        for _ in 0..(super::MAX_SCHEMA_DEPTH + 10) {
            schema = json!({
                "type": "object",
                "properties": { "x": schema },
            });
        }
        let errors = validate_schema_well_formed(&schema);
        assert!(
            errors.iter().any(|e| e.contains("maximum nesting depth")),
            "expected depth-bailout error, got {:?}",
            errors
        );
    }
}

// ===========================================================================
// Fuel-sizing check
// ===========================================================================
//
// Every number below is a real value off the live database on 2026-08-17 —
// the thirteen workflow nodes that carry both a `MAX_TOKENS` and an explicit
// `data.max_fuel`, plus the pre-#642 state of the node this check exists for.
// A synthetic fixture would prove the arithmetic and prove nothing about
// whether the arithmetic separates the fleet it has to run against.
#[cfg(test)]
mod fuel_sizing_tests {
    use super::*;

    /// `SMART_MEMORY_CONTEXT_BYTE_BUDGET`'s default. Hardcoded rather than
    /// read through `talos_config` so these tests cannot be perturbed by an
    /// env var set by another test in the same binary.
    const CTX: u64 = 12_000;

    /// (name, MAX_TOKENS, max_fuel) — every node on the live fleet with both,
    /// i.e. every node an author has deliberately sized. All are LLM nodes in
    /// memory-eligible worlds, so all take the injection allowance.
    const SIZED_FLEET: &[(&str, u64, u64)] = &[
        ("daily-crm-capture/extract", 1600, 14_000_000),
        ("pa-ask/answer", 1500, 8_000_000),
        ("pa-ask-grounded/answer", 1500, 8_000_000),
        ("pa-ask-grounded-judged/answer", 1500, 8_000_000),
        ("pa-autonomy-digest/compose", 2000, 12_000_000),
        ("pa-chief-of-staff/synthesize", 1800, 12_000_000),
        ("pa-daily-brief/brief", 1800, 8_000_000), // the tightest
        ("pa-inbox-organizer-work/classify_work", 1800, 12_000_000),
        ("pa-inbox-triage/triage", 1800, 10_000_000),
        ("pa-meeting-prep/prep", 1200, 8_000_000),
        ("pa-opportunity-crm/extract", 1600, 14_000_000),
        ("pa-quality-judge/judge", 700, 8_000_000),
        ("pa-read-later-digest/digest", 1400, 8_000_000), // post-#642
    ];

    /// **THE ACCEPTANCE TEST.** `pa-read-later-digest/digest` before #642:
    /// `MAX_TOKENS: 1400` against the shared `modules.max_fuel` of 1,404,000,
    /// with no node-scoped override at all. It ran for five weeks and failed
    /// two of its four scheduled runs.
    ///
    /// The 1,404,000 is the load-bearing detail: the node had NO
    /// `data.max_fuel`, so a check that looked only at the node's own config
    /// would have found nothing to judge and passed it silently. Reading the
    /// module default is what makes this check able to see the case.
    #[test]
    fn the_check_rejects_the_budget_that_never_fit() {
        let floor = required_fuel_floor(1400, CTX);
        assert!(
            1_404_000 < floor,
            "pre-#642 digest must fail the floor; floor={floor}"
        );
        // And the fix must pass, or the check would still be firing on a node
        // that is now correctly sized.
        assert!(
            8_000_000 >= floor,
            "post-#642 digest must pass; floor={floor}"
        );
    }

    /// The negative direction, over the whole sized fleet. A check that
    /// rejects everything is as useless as one that rejects nothing.
    #[test]
    fn the_check_passes_every_node_an_author_has_sized() {
        for (name, max_tokens, max_fuel) in SIZED_FLEET {
            let floor = required_fuel_floor(*max_tokens, CTX);
            assert!(
                *max_fuel >= floor,
                "{name} must pass: max_fuel {max_fuel} < floor {floor}"
            );
        }
    }

    /// The margin, pinned in both directions — this is the evidence that
    /// `FUEL_PER_MAX_TOKEN` is a threshold in an empty band rather than a
    /// parameter fitted to the one failure.
    ///
    /// Observed `max_fuel / MAX_TOKENS`: the sized fleet's MINIMUM is 4,444
    /// and pre-#642 digest was 1,003. Nothing lies between. So any constant
    /// in (1003, 4444) yields identical verdicts on every node that exists,
    /// and 3,000 is simply the middle of that band.
    #[test]
    fn the_threshold_sits_in_an_empty_band_and_is_not_fitted() {
        let fleet_min = SIZED_FLEET
            .iter()
            .map(|(_, mt, mf)| mf / mt)
            .min()
            .expect("non-empty");
        assert_eq!(fleet_min, 4_444, "tightest sized node on the fleet");
        // 1,404,000 / 1400 = 1002.86; integer division floors it to 1002.
        assert_eq!(1_404_000_u64 / 1400, 1_002, "pre-#642 digest");
        assert!(
            (1_002..4_444).contains(&FUEL_PER_MAX_TOKEN),
            "the constant must sit strictly inside the empty band"
        );
        // Non-vacuity: the verdicts must actually MOVE outside the band, or
        // the two tests above are asserting a tautology.
        //
        // The low arm uses 600, not something just under 1,002, because the
        // injection allowance is part of the floor: at the 12,000-byte default
        // it contributes 480,000 fuel, which on its own is a third of the bad
        // node's entire 1,404,000 budget. The per-token rate that lets that
        // node through is therefore <= (1,404,000 - 480,000) / 1400 = 660, not
        // 1,002. Worth stating because it also bounds the previous test's
        // claim precisely: the allowance flips no verdict AT THE SHIPPED
        // CONSTANT, which is not the same as never being able to flip one.
        let too_low = |mt: u64| mt * 600 + CTX * FUEL_PER_CONTEXT_BYTE;
        assert!(
            1_404_000 >= too_low(1400),
            "at 600/token the bad node passes"
        );
        let too_high = |mt: u64| mt * 5_000 + CTX * FUEL_PER_CONTEXT_BYTE;
        assert!(
            8_000_000 < too_high(1800),
            "at 5000/token pa-daily-brief/brief would be falsely flagged"
        );
    }

    /// The injection allowance is a stated margin, NOT a classifier. Dropping
    /// it to zero must change no verdict on any node of the current fleet —
    /// if it ever does, the constant has started driving decisions and needs
    /// a real measurement behind it rather than the reasoning in its doc
    /// comment.
    #[test]
    fn the_injection_allowance_is_a_margin_not_a_classifier() {
        for (name, max_tokens, max_fuel) in SIZED_FLEET {
            assert_eq!(
                *max_fuel >= required_fuel_floor(*max_tokens, CTX),
                *max_fuel >= required_fuel_floor(*max_tokens, 0),
                "{name}: the allowance flipped a verdict"
            );
        }
        assert_eq!(
            1_404_000 >= required_fuel_floor(1400, CTX),
            1_404_000 >= required_fuel_floor(1400, 0),
            "pre-#642 digest: the allowance flipped a verdict"
        );
        // It is nonetheless PRESENT and non-zero — a margin that rounds to
        // nothing would be a comment pretending to be a constant.
        assert_eq!(
            required_fuel_floor(1400, CTX) - required_fuel_floor(1400, 0),
            480_000
        );
    }

    /// Memory eligibility must agree with the engine's own gate, including
    /// the explicit-override precedence — a sizing check that disagreed about
    /// which nodes get the injection would be sizing the wrong nodes.
    #[test]
    fn memory_eligibility_mirrors_the_engine_gate() {
        // Pure-egress worlds: no injection by default.
        assert!(!node_receives_actor_context(Some("http-node"), None));
        assert!(!node_receives_actor_context(Some("network-node"), None));
        assert!(!node_receives_actor_context(Some("messaging-node"), None));
        // Everything else: injected by default. `secrets-node` is the LLM
        // template's world, i.e. the population this check judges.
        assert!(node_receives_actor_context(Some("secrets-node"), None));
        assert!(node_receives_actor_context(Some("agent-node"), None));
        assert!(node_receives_actor_context(Some("minimal-node"), None));
        // Explicit config always wins, in both directions — `needs_memory:
        // false` on a memory-eligible world SUPPRESSES the injection (and is
        // the documented fix for a node that does not consume memory), while
        // `true` on a pure-egress world forces it.
        assert!(!node_receives_actor_context(
            Some("secrets-node"),
            Some(false)
        ));
        assert!(node_receives_actor_context(Some("http-node"), Some(true)));
        // Unknown world ⇒ assume injected. The conservative direction for a
        // FLOOR: it can only raise the requirement.
        assert!(node_receives_actor_context(None, None));
    }

    /// Overflow safety. `MAX_TOKENS` is caller-authored and unvalidated at the
    /// graph level, so a `u64::MAX` must saturate rather than wrap — a wrapped
    /// floor would come out small and turn the check into a silent pass on the
    /// most absurd input it can be given.
    #[test]
    fn an_absurd_max_tokens_saturates_rather_than_wrapping() {
        assert_eq!(required_fuel_floor(u64::MAX, CTX), u64::MAX);
        assert_eq!(required_fuel_floor(u64::MAX, u64::MAX), u64::MAX);
    }
}

// ── Retry-envelope containment tests ─────────────────────────────────────────
//
// These drive `retry_envelope_overrun` — the SAME function `validate` calls to
// decide whether to emit the warning. `validate` itself only formats the
// message, so there is no second copy of the decision to drift.
#[cfg(test)]
mod retry_envelope_tests {
    use super::*;
    use serde_json::json;

    /// The observed live budget on the deployment that motivated this check.
    const BUDGET: u64 = 300;
    /// `DEFAULT_NODE_TIMEOUT_SECS` with no operator override.
    const NODE_DEFAULT: u64 = talos_workflow_engine_core::DEFAULT_NODE_TIMEOUT_SECS_FALLBACK;

    fn check(node: &serde_json::Value, budget: u64) -> Option<RetryEnvelopeOverrun> {
        // Actor-bound, and a world that resolves to ZERO default retries, so
        // any count in these cases came from the node itself unless a test
        // deliberately says otherwise.
        retry_envelope_overrun(node, budget, true, &[], Some("http-node"), NODE_DEFAULT)
    }

    /// The exact live shape, 2026-08-27: no declared `timeout_secs` (so the
    /// 120 s default applies), `retry_count: 2`, 3 s backoff, 300 s budget.
    /// 3 x 120 + (3 + 6) = 369 s. The third attempt cannot complete.
    #[test]
    fn live_shape_fires() {
        let node = json!({ "retry_count": 2, "retry_backoff_ms": 3000 });
        let o = check(&node, BUDGET).expect("369s envelope must not fit a 300s budget");
        assert_eq!(o.attempts, 3);
        assert_eq!(o.per_attempt_secs, 120);
        assert_eq!(o.resolved_retries, 2);
        assert!(o.retries_declared);
        assert_eq!(o.envelope_secs, 369);
    }

    /// The same node WITHOUT the backoff — 360 s, the figure the incident
    /// report quoted. Still over 300; the check must not depend on backoff to
    /// find it.
    #[test]
    fn plan_shape_without_declared_backoff_fires() {
        let node = json!({ "retry_count": 2 });
        let o = check(&node, BUDGET).expect("360s + default backoff must not fit 300s");
        assert_eq!(o.envelope_secs, 361); // 360 + 1.5s of default backoff, floored
    }

    /// One retry at the same timeout fits with 60 s to spare — the check must
    /// stay quiet. This is the "does not fire on a fitting one" half.
    #[test]
    fn fitting_shape_does_not_fire() {
        let node = json!({ "retry_count": 1 });
        assert!(check(&node, BUDGET).is_none());
    }

    /// Exactly filling the budget is not an overrun: the attempt CAN complete
    /// if it starts immediately. It is a hazard (nothing else may run) but not
    /// a structural impossibility, and this check only claims the latter.
    #[test]
    fn exactly_filling_the_budget_does_not_fire() {
        let node = json!({ "retry_count": 0, "timeout_secs": 300 });
        assert!(check(&node, BUDGET).is_none());
    }

    /// `execution_timeout_secs: 0` disables the workflow wall-clock cap, so
    /// there is no container for the envelope to exceed.
    #[test]
    fn disabled_budget_never_fires() {
        let node = json!({ "retry_count": 9, "timeout_secs": 600 });
        assert!(check(&node, 0).is_none());
    }

    /// A single attempt longer than the whole budget is the degenerate case of
    /// the same defect, with no retry involved at all.
    #[test]
    fn single_attempt_over_budget_fires() {
        let node = json!({ "retry_count": 0, "timeout_secs": 400 });
        let o = check(&node, BUDGET).expect("one 400s attempt cannot fit 300s");
        assert_eq!(o.attempts, 1);
        assert_eq!(o.envelope_secs, 400);
    }

    /// Per-attempt timeout precedence is `data` FIRST, matching
    /// `engine_graph_load`. A checker that read top-level first would compute
    /// 300 s here and stay silent on a node the engine runs for 60 s.
    #[test]
    fn per_attempt_timeout_reads_data_before_top_level() {
        let node = json!({ "timeout_secs": 300, "data": { "timeout_secs": 60 } });
        assert_eq!(node_per_attempt_timeout_secs(&node, NODE_DEFAULT), 60);
    }

    /// `retry_count` precedence is the OPPOSITE — top level first, matching
    /// `read_node_retry_policy`. An explicit 0 wins over a nested 5.
    #[test]
    fn retry_count_reads_top_level_before_data() {
        let node = json!({ "retry_count": 0, "data": { "retry_count": 5 } });
        assert_eq!(node_declared_u64(&node, "retry_count"), Some(0));
        assert!(check(&node, BUDGET).is_none());
    }

    /// An actor-less execution has its DECLARED count clamped to
    /// `MAX_RETRIES_UNBUDGETED` at graph load. Predicting the unclamped count
    /// would warn about an envelope the engine will never run.
    #[test]
    fn actorless_declared_count_is_clamped_before_measuring() {
        let node = json!({ "retry_count": 10, "timeout_secs": 60, "retry_backoff_ms": 0 });
        // Bound actor: 11 x 60 = 660 > 500.
        let bound = retry_envelope_overrun(&node, 500, true, &[], Some("http-node"), NODE_DEFAULT)
            .expect("11 attempts of 60s must not fit 500s");
        assert_eq!(bound.attempts, 11);
        // No actor: clamped to 3 retries ⇒ 4 x 60 = 240 ≤ 500, no warning.
        assert!(
            retry_envelope_overrun(&node, 500, false, &[], Some("http-node"), NODE_DEFAULT)
                .is_none()
        );
    }

    /// A node that declares NO retry keys still gets a count at dispatch from
    /// the method-aware classifier, so the envelope must include it — and the
    /// message must not claim the author declared it.
    #[test]
    fn absent_retry_count_uses_the_module_default() {
        let node = json!({ "id": "fetch" });
        // Read-only HTTP ⇒ DEFAULT_TRANSIENT_RETRIES (2) ⇒ 3 x 120 + 1 = 361.
        let o = retry_envelope_overrun(
            &node,
            BUDGET,
            true,
            &["GET".to_string()],
            Some("http-node"),
            NODE_DEFAULT,
        )
        .expect("classifier-supplied retries must count toward the envelope");
        assert_eq!(
            o.resolved_retries,
            talos_workflow_engine_core::DEFAULT_TRANSIENT_RETRIES
        );
        assert!(!o.retries_declared);

        // A side-effect world fails closed to 0 retries ⇒ one 120s attempt fits.
        assert!(retry_envelope_overrun(
            &node,
            BUDGET,
            true,
            &["POST".to_string()],
            Some("messaging-node"),
            NODE_DEFAULT,
        )
        .is_none());
    }

    /// The standing mandate applied to this change: an envelope calculator
    /// must not itself overflow the container it computes in. `retry_count` is
    /// capped at 100 and `2^100` does not fit in a `u64`.
    #[test]
    fn envelope_saturates_at_the_retry_cap() {
        let e = node_retry_envelope_secs(
            talos_workflow_types::MAX_NODE_TIMEOUT_SECS,
            talos_workflow_types::MAX_NODE_RETRY_COUNT,
            60_000,
        );
        // Saturated, not wrapped: the backoff term alone pins at u64::MAX ms,
        // which is u64::MAX/1000 seconds. A wrapping `<<` or `pow` would land
        // somewhere small and the check would silently pass the node.
        assert!(e >= u64::MAX / 1_000, "must saturate, not wrap (got {e})");
        // The 63/64 shift boundary must not panic in a debug build either.
        assert!(node_retry_envelope_secs(600, 63, 60_000) > 0);
        assert!(node_retry_envelope_secs(600, 64, 60_000) > 0);
        // And a small case is still exact: 4 attempts x 1s + (1+2+4)s backoff.
        assert_eq!(node_retry_envelope_secs(1, 3, 1_000), 4 + 7);
    }
}

// ── Observed-history checks ──────────────────────────────────────────────────
//
// These exercise the SAME functions `validate` calls (`chronic_node_failure`,
// `retry_headroom`, `describe_chronic_failure`) — no test-local
// reimplementation of the thresholds or the wording, because a shadow copy
// drifts and then proves nothing.
//
// The numbers in `fleet_*` come from a live `execution_events` table
// (2026-08-28) and are the calibration evidence for the constants, not
// invented inputs.
#[cfg(test)]
mod failure_history_tests {
    use super::{
        chronic_node_failure, describe_chronic_failure, history_window_days, retry_headroom,
        ChronicNodeFailure, HistoryCoverage, ObservedNodeRecord, CHRONIC_FAILURE_RATE,
        CHRONIC_MIN_ATTEMPTS, CHRONIC_MIN_FAILURES, HISTORY_MAX_EXECUTIONS, HISTORY_WINDOW_DAYS,
    };
    use serde_json::json;

    /// `DEFAULT_NODE_TIMEOUT_SECS` with no operator override.
    const NODE_DEFAULT: u64 = talos_workflow_engine_core::DEFAULT_NODE_TIMEOUT_SECS_FALLBACK;

    fn rec(attempts: i64, failures: i64, timeouts: i64) -> ObservedNodeRecord {
        ObservedNodeRecord {
            attempts,
            failures,
            timeout_failures: timeouts,
        }
    }

    /// The live node this check exists for: `daily-crm-capture/extract`.
    /// Explicit top-level `retry_count: 0`, `data.timeout_secs: 110`, inside a
    /// 180 s workflow budget.
    fn extract_node() -> serde_json::Value {
        json!({
            "id": "extract",
            "type": "f9402426-8a42-40d1-a6c2-73a64ce21165",
            "retry_count": 0,
            "data": { "timeout_secs": 110 }
        })
    }

    // ── The decision ────────────────────────────────────────────────────────

    /// The motivating case fires. 6 failures in 21 attempts = 28.6 %.
    #[test]
    fn the_live_case_fires() {
        let f = chronic_node_failure(&rec(21, 6, 6), 22, 30, None)
            .expect("6/21 must be reported — this is the workflow the check exists for");
        assert_eq!(f.observed.failures, 6);
        assert_eq!(f.observed.timeout_failures, 6);
    }

    /// Two failures is an incident, not a pattern — even at a high rate.
    #[test]
    fn two_failures_stay_quiet_regardless_of_rate() {
        assert!(chronic_node_failure(&rec(5, 2, 2), 5, 30, None).is_none());
        assert!(chronic_node_failure(&rec(2, 2, 2), 2, 30, None).is_none());
    }

    /// A denominator too small to support a percentage produces no percentage.
    /// This is also what suppresses the system-node dispatch paths that emit
    /// `node_failed` with no preceding `node_started` (observed live on
    /// `pa-meeting-prep/prep_judge`: attempts 1, failures 1).
    #[test]
    fn tiny_denominators_stay_quiet() {
        assert!(chronic_node_failure(&rec(1, 1, 1), 1, 30, None).is_none());
        assert!(chronic_node_failure(&rec(4, 3, 3), 4, 30, None).is_none());
        // One more attempt and the same 3 failures DOES fire — the boundary is
        // exactly CHRONIC_MIN_ATTEMPTS, not somewhere nearby.
        assert!(chronic_node_failure(&rec(CHRONIC_MIN_ATTEMPTS, 3, 3), 5, 30, None).is_some());
    }

    /// The rate gate is what keeps high-volume workflows quiet: their absolute
    /// failure counts clear `CHRONIC_MIN_FAILURES` easily. Every one of these
    /// is a real fleet observation over the raw 30-day view.
    #[test]
    fn fleet_high_volume_nodes_stay_quiet_on_rate() {
        for (attempts, failures, name) in [
            (2241, 10, "pa-followup-approval-notifier"),
            (4525, 12, "pa-ask-email"),
            (584, 5, "alert-triage"),
            (230, 3, "pa-inbox-organizer-work"),
        ] {
            assert!(
                chronic_node_failure(&rec(attempts, failures, 0), 50, 30, None).is_none(),
                "{name}: {failures}/{attempts} is background noise and must not warn"
            );
        }
    }

    /// The two nodes the fleet SHOULD surface, and the empty band between them
    /// and everything else. Any threshold in (0.013, 0.154) selects the same
    /// set, which is what makes 0.10 a threshold rather than a fitted value.
    #[test]
    fn fleet_calibration_band_is_empty_around_the_threshold() {
        // Fires: the two chronic nodes.
        assert!(chronic_node_failure(&rec(21, 6, 6), 22, 30, None).is_some()); // 28.6%
        assert!(chronic_node_failure(&rec(26, 4, 3), 26, 30, None).is_some()); // 15.4%
                                                                               // Nothing on the fleet with >= CHRONIC_MIN_FAILURES sits between the
                                                                               // highest quiet rate and the lowest loud one.
        let highest_quiet = 3.0 / 230.0;
        let lowest_loud = 4.0 / 26.0;
        assert!(
            highest_quiet < CHRONIC_FAILURE_RATE && CHRONIC_FAILURE_RATE < lowest_loud,
            "threshold {CHRONIC_FAILURE_RATE} must sit inside the empty band \
             ({highest_quiet}, {lowest_loud})"
        );
    }

    /// A clean node is silent no matter how many times it ran.
    #[test]
    fn zero_failures_never_fires() {
        assert!(chronic_node_failure(&rec(500, 0, 0), 50, 30, None).is_none());
        assert!(chronic_node_failure(&rec(0, 0, 0), 0, 30, None).is_none());
    }

    /// The constants are what the tests above assume. If someone retunes them,
    /// this fails before the behavioural tests do and says why.
    #[test]
    fn thresholds_are_the_calibrated_values() {
        assert_eq!(CHRONIC_MIN_FAILURES, 3);
        assert_eq!(CHRONIC_MIN_ATTEMPTS, 5);
        assert!((CHRONIC_FAILURE_RATE - 0.10).abs() < f64::EPSILON);
        assert_eq!(HISTORY_MAX_EXECUTIONS, 50);
        assert_eq!(HISTORY_WINDOW_DAYS, 30);
    }

    /// The lookback must never claim a window wider than retention can hold —
    /// a window that silently shrinks is exactly the trap this check must not
    /// walk into.
    #[test]
    fn window_never_exceeds_retention() {
        assert!(history_window_days() <= HISTORY_WINDOW_DAYS);
        assert!(history_window_days() <= talos_config::execution_retention_days());
        assert!(history_window_days() > 0);
    }

    // ── The static half ─────────────────────────────────────────────────────

    /// The live node's headroom: `retry_count` explicitly 0, per-attempt 110 s,
    /// budget 180 s. One more attempt is 2 x 110 + 60 s backoff = 280 s, which
    /// does not fit — so raising `retry_count` alone cannot help.
    #[test]
    fn live_node_has_no_retry_headroom() {
        let h = retry_headroom(
            &extract_node(),
            180,
            true,
            &[],
            Some("http-node"),
            NODE_DEFAULT,
        )
        .expect("a non-zero budget yields headroom");
        assert_eq!(h.resolved_retries, 0);
        assert!(
            h.retries_declared,
            "an explicit retry_count: 0 is a declaration, not an absent value"
        );
        assert_eq!(h.per_attempt_secs, 110);
        assert_eq!(h.budget_secs, 180);
        assert!(!h.one_more_attempt_fits);
        assert!(h.one_more_attempt_secs > 180);
    }

    /// A cheap node inside the same budget DOES have headroom, so the message
    /// gives the opposite advice. The check is not hardcoded to pessimism.
    #[test]
    fn a_cheap_node_has_retry_headroom() {
        let node = json!({"id": "cheap", "retry_count": 0, "data": {"timeout_secs": 10}});
        let h = retry_headroom(&node, 180, true, &[], Some("http-node"), NODE_DEFAULT).unwrap();
        assert!(h.one_more_attempt_fits);
    }

    /// A disabled wall-clock cap means there is no container, so there is
    /// nothing to say about fit.
    #[test]
    fn zero_budget_yields_no_headroom() {
        assert!(retry_headroom(
            &extract_node(),
            0,
            true,
            &[],
            Some("http-node"),
            NODE_DEFAULT
        )
        .is_none());
    }

    /// `retry_headroom` must resolve retries exactly as `retry_envelope_overrun`
    /// does — same declared-first precedence, same unbudgeted clamp, same
    /// method-aware default — or the two checks would print contradictory
    /// retry counts for one node.
    #[test]
    fn headroom_and_envelope_agree_on_the_resolved_retry_count() {
        let cases = [
            (
                json!({"id": "n", "retry_count": 7, "data": {"timeout_secs": 5}}),
                true,
            ),
            (
                json!({"id": "n", "retry_count": 7, "data": {"timeout_secs": 5}}),
                false,
            ),
            (
                json!({"id": "n", "data": {"retry_count": 2, "timeout_secs": 5}}),
                true,
            ),
            (json!({"id": "n", "data": {"timeout_secs": 5}}), true),
        ];
        for (node, has_actor) in cases {
            let h = retry_headroom(
                &node,
                10_000,
                has_actor,
                &[],
                Some("http-node"),
                NODE_DEFAULT,
            )
            .unwrap();
            // Force an overrun with a budget of 1 s so the envelope function
            // always returns Some and its resolution can be compared.
            let e = super::retry_envelope_overrun(
                &node,
                1,
                has_actor,
                &[],
                Some("http-node"),
                NODE_DEFAULT,
            )
            .unwrap();
            assert_eq!(
                h.resolved_retries, e.resolved_retries,
                "the two checks disagree about {node}"
            );
            assert_eq!(h.retries_declared, e.retries_declared);
            assert_eq!(h.per_attempt_secs, e.per_attempt_secs);
        }
    }

    // ── The wording ─────────────────────────────────────────────────────────

    /// The exact operator-facing text for the live case. Pinned because the
    /// whole defect was a response that read as reassuring; the replacement
    /// has to state the counts, the dominant mode, and the static fact — and
    /// must NOT assert that the current config caused the past failures.
    #[test]
    fn live_case_message_states_counts_mode_and_static_fact() {
        let headroom = retry_headroom(
            &extract_node(),
            180,
            true,
            &[],
            Some("http-node"),
            NODE_DEFAULT,
        );
        let finding = chronic_node_failure(&rec(21, 6, 6), 22, 30, headroom).unwrap();
        let msg = describe_chronic_failure(&finding, "extract");

        assert!(
            msg.contains("Node 'extract' failed 6 of its last 21 observed attempts"),
            "{msg}"
        );
        assert!(msg.contains("every one of them a timeout"), "{msg}");
        assert!(
            msg.contains("22 execution(s) in the last 30 day(s)"),
            "{msg}"
        );
        assert!(msg.contains("excluding cancelled and test runs"), "{msg}");
        assert!(msg.contains("retry_count is explicitly 0"), "{msg}");
        assert!(msg.contains("per-attempt timeout is 110s"), "{msg}");
        assert!(msg.contains("inside a 180s workflow budget"), "{msg}");
        assert!(msg.contains("NO retry fits"), "{msg}");
        // The timeout advice must be SIZED, not a blanket prohibition: with
        // one attempt of 110s inside 180s there really are ~70s of unused
        // budget, and telling the operator not to use them would be wrong.
        assert!(msg.contains("leaving ~70s of the budget unused"), "{msg}");
        assert!(
            msg.contains("timeout_secs can be raised into that room"),
            "{msg}"
        );
        assert!(
            msg.contains("only safe while retry_count stays at 0"),
            "{msg}"
        );
        // The honesty guard: an OBSERVATION, never a causal claim.
        assert!(
            msg.contains("not a claim that the current graph caused them"),
            "the message must not assert causation it cannot establish: {msg}"
        );
    }

    /// Mixed failure modes are reported as a fraction, not as "every one".
    #[test]
    fn mixed_modes_do_not_claim_all_timeouts() {
        let finding = chronic_node_failure(&rec(26, 4, 3), 26, 30, None).unwrap();
        let msg = describe_chronic_failure(&finding, "compose");
        assert!(msg.contains("3 of them timeouts"), "{msg}");
        assert!(!msg.contains("every one of them"), "{msg}");
    }

    /// No timeouts at all: no timeout clause, and no timeout-specific advice.
    #[test]
    fn non_timeout_failures_get_no_timeout_clause() {
        let finding = chronic_node_failure(&rec(20, 5, 0), 20, 30, None).unwrap();
        let msg = describe_chronic_failure(&finding, "fetch");
        assert!(!msg.contains("timeout"), "{msg}");
        assert!(
            msg.contains("failed 5 of its last 20 observed attempts"),
            "{msg}"
        );
    }

    /// A system node has no module dispatch, so the message carries the
    /// observation alone rather than inventing retry facts that do not apply.
    #[test]
    fn system_node_message_omits_the_static_half() {
        let finding = chronic_node_failure(&rec(20, 5, 5), 20, 30, None).unwrap();
        let msg = describe_chronic_failure(&finding, "prep_judge");
        assert!(!msg.contains("retry_count"), "{msg}");
        assert!(!msg.contains("workflow budget"), "{msg}");
        assert!(
            msg.contains("failed 5 of its last 20 observed attempts"),
            "{msg}"
        );
    }

    /// A node WITH headroom is told retries are available — the advice tracks
    /// the configuration rather than always recommending the same thing.
    #[test]
    fn headroom_available_changes_the_advice() {
        let node = json!({"id": "cheap", "retry_count": 0, "data": {"timeout_secs": 10}});
        let h = retry_headroom(&node, 180, true, &[], Some("http-node"), NODE_DEFAULT);
        let finding = chronic_node_failure(&rec(20, 5, 5), 20, 30, h).unwrap();
        let msg = describe_chronic_failure(&finding, "cheap");
        assert!(msg.contains("raising retry_count is available"), "{msg}");
        assert!(!msg.contains("NO retry fits"), "{msg}");
    }

    // ── Absence is not health ───────────────────────────────────────────────

    /// The three "no findings" causes must read differently. This is the whole
    /// point: `issues: []` on its own is what misled the operator.
    #[test]
    fn the_three_empty_causes_are_distinguishable() {
        let observed = HistoryCoverage::Observed {
            executions: 22,
            window_days: 30,
        };
        let empty = HistoryCoverage::Empty { window_days: 30 };
        let unavailable = HistoryCoverage::Unavailable;

        assert!(observed.consulted());
        assert!(!empty.consulted());
        assert!(!unavailable.consulted());

        // An empty window must NOT read as a clean bill of health...
        assert!(empty.note().contains("STATIC ONLY"));
        assert!(empty.note().contains("not that the workflow runs cleanly"));
        // ...and a failed read must NOT read as an empty window (#661).
        assert!(unavailable.note().contains("could NOT be read"));
        assert_ne!(empty.note(), unavailable.note());
        assert!(observed.note().contains("22 run(s)"));
    }

    /// A workflow that never ran produces no history finding — a false warning
    /// would be as wrong as the silence being fixed.
    #[test]
    fn no_history_produces_no_finding() {
        assert!(chronic_node_failure(&rec(0, 0, 0), 0, 30, None).is_none());
    }

    /// `ChronicNodeFailure` carries the sample it was drawn from, so a rendered
    /// finding can always state its own denominator rather than asserting a
    /// rate with no visible basis.
    #[test]
    fn finding_carries_its_own_denominator() {
        let f: ChronicNodeFailure = chronic_node_failure(&rec(21, 6, 6), 22, 30, None).unwrap();
        assert_eq!(f.executions_scanned, 22);
        assert_eq!(f.window_days, 30);
        assert_eq!(f.observed.attempts, 21);
    }
}

// ── Disabled-retry-protection tests ──────────────────────────────────────────
//
// These drive `disabled_retry_protection`, `latest_failure_is_transient` and
// `describe_disabled_retry_protection` — the SAME functions `validate` calls,
// never a test-local restatement of the rule. Every configuration below was
// read off the live fleet on 2026-08-28 (world, allowed_methods and
// retry_count as persisted in `workflows.graph_json` / `modules`), so a change
// that breaks the gate breaks against real graphs rather than invented ones.
#[cfg(test)]
mod disabled_retry_tests {
    use super::{
        describe_disabled_retry_protection, disabled_retry_protection, latest_failure_is_transient,
        ObservedNodeRecord,
    };
    use serde_json::json;

    fn methods(m: &[&str]) -> Vec<String> {
        m.iter().map(|s| (*s).to_string()).collect()
    }

    fn rec(attempts: i64, failures: i64) -> ObservedNodeRecord {
        ObservedNodeRecord {
            attempts,
            failures,
            timeout_failures: 0,
        }
    }

    /// `pa-daily-brief` / `gmail` — the node from the 2026-08-28 DNS incident.
    /// http world, DECLARED GET-only, explicit `retry_count: 0`. It failed
    /// after 1 attempt while `pa-inbox-organizer` / `gmail` (identical module,
    /// `retry_count: 2`) survived the same ten minutes.
    #[test]
    fn fires_on_the_incident_node() {
        let node = json!({"id": "gmail", "retry_count": 0});
        let f = disabled_retry_protection(&node, &methods(&["GET"]), Some("http-node")).unwrap();
        assert_eq!(f.world_default_retries, 2);
        assert_eq!(f.capability_world.as_deref(), Some("http-node"));
        assert_eq!(f.allowed_methods, methods(&["GET"]));
    }

    /// The healthy shape: no `retry_count` at all, so the method-aware default
    /// applies and there is nothing to report. Firing here would warn about
    /// every correctly-configured node on the fleet.
    #[test]
    fn silent_when_no_retry_count_is_declared() {
        let node = json!({"id": "gmail"});
        assert!(disabled_retry_protection(&node, &methods(&["GET"]), Some("http-node")).is_none());
    }

    /// The already-fixed sibling — `pa-inbox-organizer` / `gmail`, raised to 2
    /// on 2026-07-24. An operator who has already acted must not keep hearing
    /// about it.
    #[test]
    fn silent_when_retries_are_enabled() {
        let node = json!({"id": "gmail", "retry_count": 2});
        assert!(disabled_retry_protection(&node, &methods(&["GET"]), Some("http-node")).is_none());
    }

    /// THE NOISE GATE. A side-effecting world already resolves to 0, so an
    /// explicit 0 there AGREES with the default — reporting it would be
    /// reporting correctness as a problem, and would put a warning on exactly
    /// the nodes where a blind retry re-fires a non-idempotent send.
    #[test]
    fn silent_where_the_default_is_already_zero() {
        for (m, world) in [
            (methods(&["GET", "POST"]), "http-node"), // state-changing HTTP
            (methods(&["POST"]), "http-node"),
            (vec![], "messaging-node"),
            (vec![], "database-node"),
            (vec![], "governance-node"),
            (vec![], "network-node"),
            (vec![], ""), // unknown world fails closed
        ] {
            let node = json!({"id": "n", "retry_count": 0});
            assert!(
                disabled_retry_protection(&node, &m, Some(world)).is_none(),
                "must stay silent for world {world:?} methods {m:?}"
            );
        }
    }

    /// An EMPTY `allowed_methods` reads as "allow every verb" at the worker's
    /// enforcement point, so an http-world module that declares none is
    /// UNKNOWN, not read-only, and its default is 0. Pinned separately from
    /// the loop above because this is the one asymmetry in the three
    /// declaration lists and the easiest to "simplify" away.
    #[test]
    fn silent_for_http_with_undeclared_methods() {
        let node = json!({"id": "n", "retry_count": 0});
        assert!(disabled_retry_protection(&node, &[], Some("http-node")).is_none());
    }

    /// The gate is DELEGATED, not restated: for every configuration, the
    /// finding must fire on exactly the ones where
    /// `default_max_retries_for_module` resolves non-zero. If that function's
    /// rule ever changes, this check follows it automatically — and this test
    /// fails if someone hardcodes a parallel copy of the rule here.
    #[test]
    fn fires_exactly_where_the_module_default_is_nonzero() {
        for (m, world) in [
            (methods(&["GET"]), "http-node"),
            (methods(&["GET", "HEAD"]), "http-node"),
            (methods(&["get"]), "http"),
            (methods(&["GET", "POST"]), "http-node"),
            (vec![], "http-node"),
            (vec![], "minimal-node"),
            (vec![], "secrets-node"),
            (vec![], "agent-node"),
            (methods(&["GET"]), "agent-node"),
            (vec![], "messaging-node"),
            (vec![], "database-node"),
        ] {
            let expected =
                talos_workflow_engine_core::default_max_retries_for_module(&m, Some(world)) > 0;
            let node = json!({"id": "n", "retry_count": 0});
            assert_eq!(
                disabled_retry_protection(&node, &m, Some(world)).is_some(),
                expected,
                "gate disagreed with default_max_retries_for_module for {world:?} / {m:?}"
            );
        }
    }

    /// `retry_count` is read top-level-first then under `data`, matching
    /// `retry_envelope_overrun` and the engine. A node that declares it in the
    /// nested position must not escape the check.
    #[test]
    fn reads_nested_retry_count() {
        let node = json!({"id": "n", "data": {"retry_count": 0}});
        assert!(disabled_retry_protection(&node, &[], Some("secrets-node")).is_some());
    }

    /// The exact `log_message` `pa-daily-brief` / `gmail` recorded at
    /// 11:16:04 on 2026-08-28, copied verbatim from `execution_events`. It
    /// must classify transient — if it did not, the finding's "a retry would
    /// have been attempted" sentence would be false on the very incident that
    /// motivated the check.
    #[test]
    fn incident_message_classifies_transient() {
        let msg = "Job failed after 1 attempts: execution failure: Component returned error: \
                   list fetch: Error { code: 2, name: \"networkerror\", message: \"\" } \
                   [reason_class=dns]";
        assert_eq!(latest_failure_is_transient(Some(msg)), Some(true));
    }

    /// A permanent failure must classify as such, so the finding tells the
    /// operator retries are NOT the lever rather than sending them to add one.
    #[test]
    fn permanent_message_classifies_permanent() {
        assert_eq!(
            latest_failure_is_transient(Some("401 Unauthorized: invalid api key")),
            Some(false)
        );
    }

    /// No recorded message is not a verdict. `None` must stay `None` so the
    /// rendered text omits the clause entirely rather than guessing.
    #[test]
    fn no_message_yields_no_verdict() {
        assert_eq!(latest_failure_is_transient(None), None);
    }

    /// The full rendered finding for the incident node. Pinned because the
    /// operator-facing wording IS the deliverable here — there is no mutation,
    /// so the text is the entire product.
    #[test]
    fn renders_the_incident_finding() {
        let node = json!({"id": "gmail", "retry_count": 0});
        let f = disabled_retry_protection(&node, &methods(&["GET"]), Some("http-node")).unwrap();
        let msg =
            describe_disabled_retry_protection(&f, "gmail", Some(&rec(22, 1)), Some(true), 22, 30);
        assert!(msg.contains("sets retry_count explicitly to 0"));
        assert!(msg.contains("capability world 'http-node', allowed_methods [GET]"));
        assert!(msg.contains("resolves to 2 transient retries by default"));
        assert!(msg.contains("runs EXACTLY ONCE"));
        assert!(msg.contains("1 of its last 22 attempts failed"));
        assert!(msg.contains("across 22 execution(s) in the last 30 day(s)"));
        assert!(msg.contains("classifies as TRANSIENT"));
        assert!(msg.contains("set retry_count to 2"));
        // F2: the finding must never assert the 0 is wrong.
        assert!(msg.contains("If the 0 is deliberate, keep it"));
    }

    /// A node that has never run still gets the finding — the whole point of
    /// not gating on history. It renders no observed clause and no verdict,
    /// rather than an empty or invented one.
    #[test]
    fn renders_without_history() {
        let node = json!({"id": "poll", "retry_count": 0});
        let f = disabled_retry_protection(&node, &methods(&["GET"]), Some("http-node")).unwrap();
        let msg = describe_disabled_retry_protection(&f, "poll", None, None, 0, 30);
        assert!(msg.contains("runs EXACTLY ONCE"));
        assert!(!msg.contains("Observed:"));
        assert!(!msg.contains("TRANSIENT"));
        assert!(msg.contains("set retry_count to 2"));
    }

    /// A clean node says so explicitly — "exposure, not damage". Silence about
    /// the denominator is what let the original `issues: []` read as health.
    #[test]
    fn renders_a_clean_record_as_exposure_not_damage() {
        let node = json!({"id": "compose_reply", "retry_count": 0});
        let f = disabled_retry_protection(&node, &[], Some("minimal-node")).unwrap();
        let msg = describe_disabled_retry_protection(
            &f,
            "compose_reply",
            Some(&rec(4508, 0)),
            None,
            50,
            30,
        );
        assert!(msg.contains("has not failed in its last 4508 attempts"));
        assert!(msg.contains("exposure, not a report of damage"));
        // A pure-compute module declares no methods — do not render an empty list.
        assert!(!msg.contains("allowed_methods []"));
        assert!(msg.contains("capability world 'minimal-node'"));
    }

    /// When the last failure was permanent the finding must NOT push the
    /// operator toward a retry — that is `get_workflow_risk_assessment`'s
    /// mistake, and adding retries to a deterministic failure just burns fuel.
    #[test]
    fn permanent_last_failure_steers_away_from_retries() {
        let node = json!({"id": "extract", "retry_count": 0});
        let f = disabled_retry_protection(&node, &[], Some("secrets-node")).unwrap();
        let msg = describe_disabled_retry_protection(
            &f,
            "extract",
            Some(&rec(21, 6)),
            Some(false),
            22,
            30,
        );
        assert!(msg.contains("classifies as permanent"));
        assert!(msg.contains("retries are not the lever"));
        assert!(!msg.contains("classifies as TRANSIENT"));
    }
}

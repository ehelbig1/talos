//! How much of a workflow's wall-clock budget one dispatch attempt may
//! occupy — **the one home for that arithmetic**.
//!
//! # Why this is a crate-level module and not dispatcher-private
//!
//! Two surfaces answer the same question and they have to agree:
//!
//! * the **dispatcher** (`talos_workflow_engine_nats::dispatcher`) decides,
//!   per attempt, how long to wait — and a wrong answer there is a real
//!   cancellation;
//! * the **validator** (`talos_workflow_validation`) tells an operator, before
//!   the run, whether the node's configured allowance will actually be granted
//!   — and a wrong answer there is advice acted on.
//!
//! Until #764 the dispatcher owned `clamp_attempt_timeout`,
//! `BUDGET_RESERVE_SECS`, `MIN_REMAINING_FOR_ATTEMPT_SECS` and
//! `TOKIO_WRAP_GRACE_SECS` as `pub(crate)`/private items, and the validator
//! carried its own, simpler fit test: `envelope_secs <= budget_secs`. Those two
//! disagree by exactly `TOKIO_WRAP_GRACE_SECS + BUDGET_RESERVE_SECS` = **7 s**
//! at the boundary, so a node configured at 120 s inside a 120 s budget was
//! reported as fitting and clamped to 118 s (measured live: 117 s, since
//! `Duration::as_secs` truncates the sub-second gap between the deadline stamp
//! and the dispatch) on attempt 1 of every run. Nine such nodes across three
//! ACTIVE workflows on the reference fleet, 2 326 clamped attempts per 48 h.
//!
//! # The arithmetic, stated once
//!
//! * A node's **allowance** is its per-attempt wire timeout plus
//!   [`TOKIO_WRAP_GRACE_SECS`] — the dispatcher's outer cancellation wrap is
//!   deliberately looser than the wire budget the worker enforces, so the
//!   sandbox gets to finish and report rather than being cancelled underneath.
//!   [`dispatch_allowance_secs`] is that sum; do not re-add the 5 anywhere.
//! * An attempt is granted `min(allowance, remaining − BUDGET_RESERVE_SECS)`.
//! * With less than [`MIN_REMAINING_FOR_ATTEMPT_SECS`] left it is not started.
//!
//! # What this module does NOT decide
//!
//! Routing. A clamped attempt that times out is an ordinary node failure the
//! engine routes (error edges, `continue_on_error`, DLQ); a `BudgetExhausted`
//! attempt is an ordinary node failure that never touched the wire. Neither is
//! a reactor drop — see [`simulate_attempt_sequence`] for the residual case
//! where a drop is still the outcome.

use std::time::Instant;

/// Seconds of the workflow's remaining wall-clock budget held back from a
/// clamped attempt so the engine can still RECORD the failure.
///
/// A node failure is only worth more than a reactor drop because
/// `handle_node_failure` gets to run: it `await`s a `node_failed` INSERT, fires
/// the DLQ write, reaps sibling `module_executions` rows, and — for a node with
/// an error edge or `__continue_on_error` — lets the workflow carry on.
/// Clamping to exactly the remaining budget would race all of that against the
/// wall-clock timeout and usually lose, converting the fix back into the bug.
///
/// It makes the recording LIKELY, not certain: a failure path that takes longer
/// than this still loses the race and the reactor future is dropped.
pub const BUDGET_RESERVE_SECS: u64 = 2;

/// Below this much remaining budget an attempt is not started at all.
///
/// One second is the smallest attempt window this clamp will ever hand out;
/// anything less cannot complete a NATS round-trip plus worker admission, so
/// starting it removes no success that would otherwise have happened — while
/// consuming the reserve the failure path needs.
pub const MIN_REMAINING_FOR_ATTEMPT_SECS: u64 = BUDGET_RESERVE_SECS + 1;

/// Slack added to the dispatcher's outer cancellation timeout so the
/// worker-side sandbox can finish gracefully before the outer timer cancels the
/// request.
///
/// The wire-format `timeout_ms` stays at the bare per-node budget — only the
/// cancellation wrap around the retry loop gets this extra grace, which is why
/// a node "configured for 120 s" is really asking the workflow budget for 125.
pub const TOKIO_WRAP_GRACE_SECS: u64 = 5;

/// The allowance the dispatcher actually clamps: a node's per-attempt wire
/// timeout plus [`TOKIO_WRAP_GRACE_SECS`].
///
/// Exists so the `+ 5` has one statement. The dispatcher applies it at the
/// `execute_job_with_retry` call site; the validator applies it when it
/// simulates the same sequence.
#[must_use]
pub fn dispatch_allowance_secs(per_attempt_timeout_secs: u64) -> u64 {
    per_attempt_timeout_secs.saturating_add(TOKIO_WRAP_GRACE_SECS)
}

/// How long the retry loop may wait on one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptWindow {
    /// Wait up to `secs`. `clamped` is true when the WORKFLOW budget — not the
    /// node's own allowance — set the ceiling, which is what makes a resulting
    /// timeout attributable to "out of budget" rather than "too slow".
    Wait {
        /// The granted window, in seconds.
        secs: u64,
        /// `true` when the workflow budget, not the node allowance, set it.
        clamped: bool,
    },
    /// Too little budget remains to run an attempt AND still record the
    /// failure. `remaining_secs` is what was left.
    BudgetExhausted {
        /// Seconds of workflow budget left when the attempt was refused.
        remaining_secs: u64,
    },
}

impl AttemptWindow {
    /// The granted window, or `None` when the attempt was not started.
    #[must_use]
    pub fn granted_secs(&self) -> Option<u64> {
        match self {
            Self::Wait { secs, .. } => Some(*secs),
            Self::BudgetExhausted { .. } => None,
        }
    }

    /// `true` when the attempt started but got less than its allowance.
    #[must_use]
    pub fn is_clamped(&self) -> bool {
        matches!(self, Self::Wait { clamped: true, .. })
    }
}

/// The window for one attempt, given the node's allowance and the seconds of
/// workflow budget that remain.
///
/// **This is the arithmetic.** [`clamp_attempt_timeout`] is the `Instant`-typed
/// entry point the dispatcher uses; [`simulate_attempt_sequence`] is the
/// seconds-typed one the validator uses. Both route here so the two surfaces
/// cannot answer differently.
#[must_use]
pub fn attempt_window_for_remaining(
    node_allowance_secs: u64,
    remaining_secs: u64,
) -> AttemptWindow {
    if remaining_secs < MIN_REMAINING_FOR_ATTEMPT_SECS {
        return AttemptWindow::BudgetExhausted { remaining_secs };
    }
    let budgeted = remaining_secs - BUDGET_RESERVE_SECS;
    if budgeted >= node_allowance_secs {
        AttemptWindow::Wait {
            secs: node_allowance_secs,
            clamped: false,
        }
    } else {
        AttemptWindow::Wait {
            secs: budgeted,
            clamped: true,
        }
    }
}

/// Clamp one attempt's outer cancellation window to
/// `min(node_allowance, remaining_budget − reserve)`.
///
/// Called once per attempt (not once per dispatch) so attempt 3 sees the budget
/// attempts 1 and 2 consumed — computing it once before the loop is the bug
/// this exists to fix, one level up.
///
/// # Invariants
///
/// * The returned `secs` is **never greater than `node_allowance_secs`**. The
///   clamp can only shorten a wait, never lengthen one.
/// * It never changes the number of attempts upward. `BudgetExhausted` ends the
///   loop; `Wait` neither adds nor removes an attempt.
/// * `deadline == None` returns `Wait { node_allowance_secs, false }` —
///   byte-identical to the pre-clamp behaviour, which is what every caller that
///   does not track a workflow budget gets.
/// * `Duration::as_secs` truncates toward zero, so the remaining budget is
///   understated by up to a second. That is the conservative direction (a
///   slightly tighter clamp), deliberately not rounded up.
#[must_use]
pub fn clamp_attempt_timeout(
    node_allowance_secs: u64,
    deadline: Option<Instant>,
    now: Instant,
) -> AttemptWindow {
    let Some(deadline) = deadline else {
        return AttemptWindow::Wait {
            secs: node_allowance_secs,
            clamped: false,
        };
    };
    attempt_window_for_remaining(
        node_allowance_secs,
        deadline.saturating_duration_since(now).as_secs(),
    )
}

/// Why an attempt was clamped.
///
/// The distinction is the difference between a log line that fires on every
/// healthy run and one worth waking someone for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClampCause {
    /// The node's allowance could never have fitted this budget, even at
    /// `t = 0` with nothing consumed. Nothing that happened at runtime caused
    /// it; the graph did. This is a VALIDATION finding, reported before the run
    /// by `talos_workflow_validation`.
    Configuration,
    /// The allowance would have fitted at `t = 0`; earlier attempts, upstream
    /// nodes or siblings spent the budget first. This one is about the run.
    Consumption,
    /// The total budget is not known at this call site, so the two cannot be
    /// told apart. Treated as [`Self::Consumption`] by every caller that has to
    /// choose — the loud direction.
    Unknown,
}

impl ClampCause {
    /// Stable token for structured logs / metric labels. A closed set of
    /// `&'static str`, safe as a label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Configuration => "configuration",
            Self::Consumption => "consumption",
            Self::Unknown => "unknown",
        }
    }
}

/// Attribute a clamp to the graph or to the run.
///
/// `budget_secs` is the run's TOTAL wall-clock budget — not what remains.
/// `None` (a dispatch that carries a deadline but no budget) yields
/// [`ClampCause::Unknown`], which callers must treat as the loud case: a
/// demotion is only safe when configuration can be PROVEN to be the cause.
#[must_use]
pub fn clamp_cause(node_allowance_secs: u64, budget_secs: Option<u64>) -> ClampCause {
    match budget_secs {
        None => ClampCause::Unknown,
        Some(budget) => {
            // "Would it have clamped at t = 0?" is exactly the same question
            // the clamp answers, asked with `remaining == budget`.
            if attempt_window_for_remaining(node_allowance_secs, budget)
                == (AttemptWindow::Wait {
                    secs: node_allowance_secs,
                    clamped: false,
                })
            {
                ClampCause::Consumption
            } else {
                ClampCause::Configuration
            }
        }
    }
}

// ── Simulating the whole configured attempt sequence ────────────────────────

/// Attempts the simulation will walk before it stops recording.
///
/// `talos_workflow_types::MAX_RETRY_COUNT` is 100, and `validate_graph_timeouts`
/// rejects a higher `retry_count` as an Error, so 101 attempts covers every
/// graph the platform accepts. The cap also bounds the loop for a caller that
/// hands in an unvalidated count (`resolved_node_retries` saturates to
/// `u32::MAX`) — [`AttemptSequence::configured_attempts`] still reports the true
/// figure, so a capped walk under-reports rather than lying.
pub const MAX_SIMULATED_ATTEMPTS: u32 = 101;

/// One attempt of a simulated sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimulatedAttempt {
    /// 1-based attempt number.
    pub attempt: u32,
    /// The window this attempt would be granted.
    pub window: AttemptWindow,
}

/// What the configured attempt sequence actually gets, once the clamp is
/// applied to every attempt in turn.
///
/// Worst case by construction: every attempt is assumed to run to the full end
/// of its granted window before the next one starts, plus the exponential
/// backoff slept between them. That is the same worst case the configured
/// envelope describes — the difference is that this one is what the ENGINE
/// does with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptSequence {
    /// The node's per-attempt allowance ([`dispatch_allowance_secs`]).
    pub node_allowance_secs: u64,
    /// The workflow's wall-clock budget the sequence has to fit inside.
    pub budget_secs: u64,
    /// Attempts the configuration asks for (`retries + 1`), whatever the
    /// simulation managed to walk.
    pub configured_attempts: u32,
    /// One entry per attempt walked, in order. Ends at the first
    /// [`AttemptWindow::BudgetExhausted`], which is recorded.
    pub attempts: Vec<SimulatedAttempt>,
}

/// How a node's configured attempt sequence fares against its budget.
///
/// Three grades, and the middle one is the grade the platform had no way to
/// say: it is not an overrun (every configured attempt starts and can still
/// succeed) and it is not nothing (the node never gets the allowance its author
/// configured).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptFit {
    /// Every configured attempt starts and is granted its full allowance.
    Full,
    /// Every configured attempt starts; at least one is granted LESS than the
    /// node's allowance. Such an attempt can still succeed — inside the shorter
    /// window — and if it times out it fails the NODE, which the engine routes.
    Clamped {
        /// 1-based number of the first attempt that was cut short.
        first_clamped_attempt: u32,
        /// Seconds that attempt was granted.
        granted_secs: u64,
    },
    /// At least one configured attempt is never started: the budget is spent
    /// before it. This — and only this — is "a configured attempt can never
    /// complete".
    Truncated {
        /// Attempts that would actually start.
        started: u32,
        /// Attempts the configuration asks for.
        configured: u32,
        /// Budget left when the first refused attempt came due.
        remaining_secs: u64,
    },
}

impl AttemptFit {
    /// `true` for [`Self::Full`] — nothing to report.
    #[must_use]
    pub fn is_full(&self) -> bool {
        matches!(self, Self::Full)
    }
}

impl AttemptSequence {
    /// Attempts that would actually start.
    #[must_use]
    pub fn started(&self) -> u32 {
        u32::try_from(
            self.attempts
                .iter()
                .filter(|a| a.window.granted_secs().is_some())
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    /// The grade. See [`AttemptFit`].
    #[must_use]
    pub fn fit(&self) -> AttemptFit {
        if let Some(refused) = self
            .attempts
            .iter()
            .find(|a| matches!(a.window, AttemptWindow::BudgetExhausted { .. }))
        {
            let AttemptWindow::BudgetExhausted { remaining_secs } = refused.window else {
                unreachable!("find matched BudgetExhausted")
            };
            return AttemptFit::Truncated {
                started: refused.attempt.saturating_sub(1),
                configured: self.configured_attempts,
                remaining_secs,
            };
        }
        if let Some(first) = self.attempts.iter().find(|a| a.window.is_clamped()) {
            return AttemptFit::Clamped {
                first_clamped_attempt: first.attempt,
                granted_secs: first.window.granted_secs().unwrap_or(0),
            };
        }
        AttemptFit::Full
    }
}

/// Walk a node's configured attempt sequence through the real clamp.
///
/// `budget_secs == 0` means the workflow wall-clock cap is disabled — there is
/// no container, so every attempt gets its full allowance and the result is
/// [`AttemptFit::Full`] by construction (the dispatcher gets `deadline: None`
/// on such a run, which the clamp passes through unchanged).
#[must_use]
pub fn simulate_attempt_sequence(
    per_attempt_secs: u64,
    retries: u32,
    base_backoff_ms: u64,
    budget_secs: u64,
) -> AttemptSequence {
    let node_allowance_secs = dispatch_allowance_secs(per_attempt_secs);
    let configured_attempts = retries.saturating_add(1);
    let walk = configured_attempts.min(MAX_SIMULATED_ATTEMPTS);
    let mut attempts = Vec::with_capacity(walk as usize);

    if budget_secs == 0 {
        for attempt in 1..=walk {
            attempts.push(SimulatedAttempt {
                attempt,
                window: AttemptWindow::Wait {
                    secs: node_allowance_secs,
                    clamped: false,
                },
            });
        }
        return AttemptSequence {
            node_allowance_secs,
            budget_secs,
            configured_attempts,
            attempts,
        };
    }

    let mut elapsed_secs: u64 = 0;
    for attempt in 1..=walk {
        let remaining = budget_secs.saturating_sub(elapsed_secs);
        let window = attempt_window_for_remaining(node_allowance_secs, remaining);
        attempts.push(SimulatedAttempt { attempt, window });
        let Some(granted) = window.granted_secs() else {
            break;
        };
        elapsed_secs = elapsed_secs.saturating_add(granted);
        if attempt < walk {
            // Mirrors the dispatcher's `base_backoff_ms * 2^(n-1)`. Jitter
            // (up to +25 % per sleep) is excluded, so this under-states the
            // elapsed time — the conservative direction for a check that
            // reports a problem.
            let shift = attempt.saturating_sub(1).min(63);
            let growth = 1u64 << shift;
            let backoff_secs = base_backoff_ms.saturating_mul(growth) / 1_000;
            elapsed_secs = elapsed_secs.saturating_add(backoff_secs);
        }
    }

    AttemptSequence {
        node_allowance_secs,
        budget_secs,
        configured_attempts,
        attempts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_grace_has_one_statement() {
        assert_eq!(dispatch_allowance_secs(120), 125);
        assert_eq!(dispatch_allowance_secs(0), TOKIO_WRAP_GRACE_SECS);
        assert_eq!(dispatch_allowance_secs(u64::MAX), u64::MAX);
    }

    /// The dispatcher's `Instant` entry point and the validator's seconds entry
    /// point must be one arithmetic. If they ever diverge, the validator is
    /// once again describing an engine it does not share code with.
    #[test]
    fn the_instant_path_and_the_seconds_path_agree() {
        let now = Instant::now();
        for allowance in [0u64, 1, 5, 118, 125, 600] {
            for remaining in [0u64, 1, 2, 3, 4, 90, 118, 120, 125, 127, 300] {
                let via_instant = clamp_attempt_timeout(
                    allowance,
                    Some(now + Duration::from_secs(remaining)),
                    now,
                );
                let via_secs = attempt_window_for_remaining(allowance, remaining);
                assert_eq!(
                    via_instant, via_secs,
                    "allowance={allowance} rem={remaining}"
                );
            }
        }
    }

    #[test]
    fn no_deadline_is_the_pre_clamp_behaviour() {
        assert_eq!(
            clamp_attempt_timeout(125, None, Instant::now()),
            AttemptWindow::Wait {
                secs: 125,
                clamped: false
            }
        );
    }

    #[test]
    fn a_clamp_never_lengthens_a_wait() {
        for allowance in [1u64, 5, 125, 600] {
            for remaining in 0..400u64 {
                if let Some(secs) =
                    attempt_window_for_remaining(allowance, remaining).granted_secs()
                {
                    assert!(secs <= allowance, "allowance={allowance} rem={remaining}");
                }
            }
        }
    }

    /// The live `pa-ask-email` shape: a 120 s node inside a 120 s budget, with
    /// nothing consumed. This is the 7 s the two implementations disagreed by.
    #[test]
    fn the_live_120_in_120_shape_is_clamped_at_t_zero() {
        let w = attempt_window_for_remaining(dispatch_allowance_secs(120), 120);
        assert_eq!(
            w,
            AttemptWindow::Wait {
                secs: 118,
                clamped: true
            }
        );
        assert_eq!(
            clamp_cause(dispatch_allowance_secs(120), Some(120)),
            ClampCause::Configuration
        );
    }

    /// The shape #686 was written for: 120 s node, 300 s budget, 252 s spent.
    /// Nothing about the graph is wrong; the run consumed the budget.
    #[test]
    fn a_clamp_after_the_budget_was_spent_is_consumption() {
        let allowance = dispatch_allowance_secs(120);
        assert_eq!(
            attempt_window_for_remaining(allowance, 48),
            AttemptWindow::Wait {
                secs: 46,
                clamped: true
            }
        );
        assert_eq!(clamp_cause(allowance, Some(300)), ClampCause::Consumption);
    }

    /// An unknown budget must NOT be demoted — the loud direction.
    #[test]
    fn an_unknown_budget_is_not_attributed_to_configuration() {
        assert_eq!(clamp_cause(125, None), ClampCause::Unknown);
        assert_eq!(ClampCause::Unknown.as_str(), "unknown");
        assert_eq!(ClampCause::Configuration.as_str(), "configuration");
        assert_eq!(ClampCause::Consumption.as_str(), "consumption");
    }

    #[test]
    fn below_the_floor_no_attempt_is_started() {
        for remaining in 0..MIN_REMAINING_FOR_ATTEMPT_SECS {
            assert_eq!(
                attempt_window_for_remaining(1, remaining),
                AttemptWindow::BudgetExhausted {
                    remaining_secs: remaining
                }
            );
        }
    }

    // ── the simulation ──────────────────────────────────────────────────

    #[test]
    fn an_ample_budget_grants_every_attempt_in_full() {
        let s = simulate_attempt_sequence(30, 2, 500, 300);
        assert_eq!(s.configured_attempts, 3);
        assert_eq!(s.started(), 3);
        assert_eq!(s.fit(), AttemptFit::Full);
    }

    /// `pa-ask-email/verify_extract`: one attempt, 120 s, 120 s budget.
    #[test]
    fn a_single_attempt_that_fills_its_budget_is_clamped_not_truncated() {
        let s = simulate_attempt_sequence(120, 0, 500, 120);
        assert_eq!(s.started(), 1);
        assert_eq!(
            s.fit(),
            AttemptFit::Clamped {
                first_clamped_attempt: 1,
                granted_secs: 118
            }
        );
    }

    /// `pa-ask-email/fetch`: 3 × 120 s inside 120 s. Attempt 1 gets 118 s;
    /// attempt 2 comes due with 2 s left and is never started.
    #[test]
    fn a_retry_sequence_that_outruns_its_budget_is_truncated() {
        let s = simulate_attempt_sequence(120, 2, 500, 120);
        assert_eq!(s.started(), 1);
        assert_eq!(
            s.fit(),
            AttemptFit::Truncated {
                started: 1,
                configured: 3,
                remaining_secs: 2
            }
        );
    }

    /// A live fleet shape verbatim: 4 × 120 s with a 5 s base backoff inside
    /// a 450 s budget. All four attempts start;
    /// the fourth is cut to 38 s. The pre-#764 check called this "an attempt
    /// that can never complete", which it is not.
    #[test]
    fn a_final_attempt_cut_short_is_clamped_not_truncated() {
        let s = simulate_attempt_sequence(120, 3, 5_000, 450);
        assert_eq!(s.started(), 4);
        assert_eq!(
            s.fit(),
            AttemptFit::Clamped {
                first_clamped_attempt: 4,
                granted_secs: 38
            }
        );
    }

    #[test]
    fn a_disabled_wall_clock_cap_clamps_nothing() {
        let s = simulate_attempt_sequence(600, 5, 500, 0);
        assert_eq!(s.started(), 6);
        assert_eq!(s.fit(), AttemptFit::Full);
    }

    /// An unvalidated count must not spin the loop; the reported count stays
    /// honest.
    #[test]
    fn the_walk_is_bounded_and_says_so() {
        let s = simulate_attempt_sequence(1, u32::MAX - 1, 0, u64::MAX);
        assert_eq!(s.configured_attempts, u32::MAX);
        assert_eq!(s.attempts.len(), MAX_SIMULATED_ATTEMPTS as usize);
        assert_eq!(s.fit(), AttemptFit::Full);
    }

    /// Backoff is part of the elapsed clock, not just the attempts.
    #[test]
    fn backoff_consumes_budget_between_attempts() {
        // 2 × 10 s attempts (allowance 15) inside 60 s: without backoff both
        // fit in full. With a 30 s base backoff the second is clamped.
        assert_eq!(
            simulate_attempt_sequence(10, 1, 0, 60).fit(),
            AttemptFit::Full
        );
        assert_eq!(
            simulate_attempt_sequence(10, 1, 30_000, 60).fit(),
            AttemptFit::Clamped {
                first_clamped_attempt: 2,
                granted_secs: 13
            }
        );
    }
}

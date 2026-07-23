//! Pure statistics kernel for memory-grounding evaluation.
//!
//! Two analyses, both dependency-free and unit-tested without a runtime:
//!
//! 1. **Paired A/B** ([`aggregate_paired`]) — the causal experiment. Each eval
//!    task is run twice (memory grounding ON vs OFF) and judged; we aggregate
//!    the paired deltas into a mean lift, per-arm pass rates, a win/loss/tie
//!    tally, and a two-sided sign test so a small favourable mean isn't
//!    over-read as signal.
//!
//! 2. **Observational** ([`analyze_observational`]) — the cheap correlational
//!    signal from already-accrued provenance: within executions that DID carry
//!    memory, does higher memory relevance (`fused_score`) track a better judge
//!    outcome? This can never prove causation (memory-OFF runs leave no
//!    provenance rows), so it is reported as correlation only.

use serde::Serialize;

/// Scores within this distance are treated as a tie (judge scores are
/// continuous in [0,1]; exact equality is possible, e.g. both 1.0).
const TIE_EPSILON: f64 = 1e-9;

/// Minimum mean lift (on the [0,1] judge scale) to call a direction at all —
/// below this the effect is too small to matter even if statistically clean.
const LIFT_DELTA_THRESHOLD: f64 = 0.02;

/// Sign-test p-value at/under which we treat the direction as not-just-noise.
const LIFT_P_THRESHOLD: f64 = 0.10;

/// One eval task run under both arms and judged. Scores are the judge's
/// quality rating in [0,1]; `passed` is the judge's boolean gate.
#[derive(Clone, Debug)]
pub struct PairedResult {
    pub task_label: String,
    pub score_on: f64,
    pub score_off: f64,
    pub passed_on: bool,
    pub passed_off: bool,
}

/// The direction verdict for a paired A/B, combining effect size AND
/// significance — neither alone is enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiftVerdict {
    /// Memory grounding measurably HELPS (mean lift ≥ threshold and the
    /// win/loss split is unlikely under chance).
    Improves,
    /// Memory grounding measurably HURTS (symmetric to `Improves`).
    Regresses,
    /// Too small or too noisy to call — the honest default.
    Inconclusive,
}

/// Aggregate outcome of a paired A/B run.
#[derive(Clone, Debug, Serialize)]
pub struct EvalSummary {
    pub n: usize,
    pub mean_score_on: f64,
    pub mean_score_off: f64,
    /// mean(score_on − score_off) — the headline lift, on the [0,1] scale.
    pub mean_delta: f64,
    pub pass_rate_on: f64,
    pub pass_rate_off: f64,
    /// Tasks where ON scored higher than OFF (beyond `TIE_EPSILON`).
    pub wins: usize,
    pub losses: usize,
    pub ties: usize,
    /// Two-sided sign-test p-value over (wins, losses); 1.0 when all ties.
    pub sign_test_p: f64,
    pub verdict: LiftVerdict,
}

/// Aggregate a set of paired results. Empty input yields an all-zero summary
/// with an `Inconclusive` verdict (nothing was measured).
pub fn aggregate_paired(results: &[PairedResult]) -> EvalSummary {
    let n = results.len();
    if n == 0 {
        return EvalSummary {
            n: 0,
            mean_score_on: 0.0,
            mean_score_off: 0.0,
            mean_delta: 0.0,
            pass_rate_on: 0.0,
            pass_rate_off: 0.0,
            wins: 0,
            losses: 0,
            ties: 0,
            sign_test_p: 1.0,
            verdict: LiftVerdict::Inconclusive,
        };
    }
    let nf = n as f64;
    let sum_on: f64 = results.iter().map(|r| r.score_on).sum();
    let sum_off: f64 = results.iter().map(|r| r.score_off).sum();
    let mean_score_on = sum_on / nf;
    let mean_score_off = sum_off / nf;
    // Mean of the per-task deltas (== difference of means, but computed
    // paired to make the intent explicit).
    let mean_delta = results
        .iter()
        .map(|r| r.score_on - r.score_off)
        .sum::<f64>()
        / nf;
    let pass_rate_on = results.iter().filter(|r| r.passed_on).count() as f64 / nf;
    let pass_rate_off = results.iter().filter(|r| r.passed_off).count() as f64 / nf;

    let mut wins = 0usize;
    let mut losses = 0usize;
    let mut ties = 0usize;
    for r in results {
        let d = r.score_on - r.score_off;
        if d > TIE_EPSILON {
            wins += 1;
        } else if d < -TIE_EPSILON {
            losses += 1;
        } else {
            ties += 1;
        }
    }

    let sign_test_p = two_sided_sign_test(wins, losses);
    let verdict = if mean_delta >= LIFT_DELTA_THRESHOLD && sign_test_p <= LIFT_P_THRESHOLD {
        LiftVerdict::Improves
    } else if mean_delta <= -LIFT_DELTA_THRESHOLD && sign_test_p <= LIFT_P_THRESHOLD {
        LiftVerdict::Regresses
    } else {
        LiftVerdict::Inconclusive
    };

    EvalSummary {
        n,
        mean_score_on,
        mean_score_off,
        mean_delta,
        pass_rate_on,
        pass_rate_off,
        wins,
        losses,
        ties,
        sign_test_p,
        verdict,
    }
}

/// Two-sided sign test: under H0 (ON and OFF equally likely to win), the number
/// of wins is Binomial(n = wins+losses, p = 0.5). Returns the two-sided p-value
/// = P(|deviation| ≥ observed). Ties are excluded (they carry no directional
/// information). Returns 1.0 when there are no non-tie pairs.
pub fn two_sided_sign_test(wins: usize, losses: usize) -> f64 {
    let n = wins + losses;
    if n == 0 {
        return 1.0;
    }
    let k = wins.max(losses);
    // Sum the upper tail P(X >= k) with X ~ Binomial(n, 0.5), computed via an
    // incremental binomial coefficient to avoid overflow, then × 0.5^n.
    // 0.5^n underflows to 0 only for n well beyond any realistic eval set;
    // guard by scaling coefficients down as we go.
    let mut tail = 0.0f64;
    // term_i = C(n, i) * 0.5^n, computed iteratively from term_n = 0.5^n.
    // Simpler and numerically safe for our n (tens–hundreds): accumulate
    // C(n,i) as f64 and multiply by 0.5^n once at the end using ln-space if
    // needed. For n <= ~1000 the direct product stays finite.
    let log_half_pow_n = (n as f64) * 0.5f64.ln();
    for i in k..=n {
        let log_c = ln_binom(n, i);
        tail += (log_c + log_half_pow_n).exp();
    }
    (2.0 * tail).min(1.0)
}

/// Natural log of the binomial coefficient C(n, k), via lgamma. Stable for
/// large n where the raw coefficient would overflow.
fn ln_binom(n: usize, k: usize) -> f64 {
    if k > n {
        return f64::NEG_INFINITY;
    }
    ln_factorial(n) - ln_factorial(k) - ln_factorial(n - k)
}

/// ln(x!) via the Lanczos-free lgamma of (x+1). Uses `f64::ln_gamma` is not
/// stable, so we sum logs for our small-to-moderate n (exact and simple).
fn ln_factorial(x: usize) -> f64 {
    // Sum of ln(i) for i in 2..=x. O(x) but x is at most the eval-set size.
    let mut acc = 0.0f64;
    for i in 2..=x {
        acc += (i as f64).ln();
    }
    acc
}

// ─── Observational correlation ────────────────────────────────────────────

/// One execution's memory footprint joined to its outcome. Values-free
/// (features + labels only), mirrored from `execution_memory_context` +
/// `judge_scores`. The service maps DB rows into these.
#[derive(Clone, Debug)]
pub struct ObservationalRow {
    /// Mean fused rank score across the memories injected into this execution.
    pub mean_fused: f64,
    /// Count of memories injected.
    pub mem_count: i64,
    /// Newest judge verdict for the execution, if any.
    pub judge_passed: Option<bool>,
    pub judge_score: Option<f64>,
}

/// Correlational report: does higher memory relevance track a better outcome?
#[derive(Clone, Debug, Serialize)]
pub struct ObservationalReport {
    /// Executions with a judge label (the analyzable set).
    pub n_labeled: usize,
    /// Overall judge pass rate across labeled executions.
    pub overall_pass_rate: f64,
    /// Point-biserial (Pearson) correlation between mean fused relevance and
    /// judge pass (0/1). Positive → relevance tracks passing. `None` when
    /// there is too little data or no variance to compute it.
    pub corr_relevance_pass: Option<f64>,
    /// Correlation between memory count and judge pass. `None` as above.
    pub corr_count_pass: Option<f64>,
    /// Pass rate among the higher-relevance half (mean_fused ≥ median).
    pub pass_rate_high_relevance: Option<f64>,
    /// Pass rate among the lower-relevance half.
    pub pass_rate_low_relevance: Option<f64>,
    /// Mean judge score across labeled executions (ignores rows w/o a score).
    pub mean_judge_score: Option<f64>,
}

/// Analyze observational rows. Only rows carrying a judge verdict
/// (`judge_passed = Some`) are analyzable; the rest are ignored (an
/// execution with no judge node can't tell us about outcome).
pub fn analyze_observational(rows: &[ObservationalRow]) -> ObservationalReport {
    let labeled: Vec<&ObservationalRow> =
        rows.iter().filter(|r| r.judge_passed.is_some()).collect();
    let n = labeled.len();
    if n == 0 {
        return ObservationalReport {
            n_labeled: 0,
            overall_pass_rate: 0.0,
            corr_relevance_pass: None,
            corr_count_pass: None,
            pass_rate_high_relevance: None,
            pass_rate_low_relevance: None,
            mean_judge_score: None,
        };
    }
    let nf = n as f64;
    let passed: Vec<f64> = labeled
        .iter()
        .map(|r| {
            if r.judge_passed == Some(true) {
                1.0
            } else {
                0.0
            }
        })
        .collect();
    let overall_pass_rate = passed.iter().sum::<f64>() / nf;

    let relevance: Vec<f64> = labeled.iter().map(|r| r.mean_fused).collect();
    let counts: Vec<f64> = labeled.iter().map(|r| r.mem_count as f64).collect();
    let corr_relevance_pass = pearson(&relevance, &passed);
    let corr_count_pass = pearson(&counts, &passed);

    // Median split on relevance → compare pass rates of the two halves.
    let (pass_rate_high_relevance, pass_rate_low_relevance) =
        median_split_pass(&relevance, &passed);

    // Mean judge score over rows that carry a numeric score.
    let scores: Vec<f64> = labeled.iter().filter_map(|r| r.judge_score).collect();
    let mean_judge_score = if scores.is_empty() {
        None
    } else {
        Some(scores.iter().sum::<f64>() / scores.len() as f64)
    };

    ObservationalReport {
        n_labeled: n,
        overall_pass_rate,
        corr_relevance_pass,
        corr_count_pass,
        pass_rate_high_relevance,
        pass_rate_low_relevance,
        mean_judge_score,
    }
}

/// Pearson correlation. `None` when n < 2 or either series has zero variance.
fn pearson(x: &[f64], y: &[f64]) -> Option<f64> {
    let n = x.len();
    if n < 2 || y.len() != n {
        return None;
    }
    let nf = n as f64;
    let mx = x.iter().sum::<f64>() / nf;
    let my = y.iter().sum::<f64>() / nf;
    let mut sxy = 0.0;
    let mut sxx = 0.0;
    let mut syy = 0.0;
    for i in 0..n {
        let dx = x[i] - mx;
        let dy = y[i] - my;
        sxy += dx * dy;
        sxx += dx * dx;
        syy += dy * dy;
    }
    if sxx <= f64::EPSILON || syy <= f64::EPSILON {
        return None;
    }
    Some(sxy / (sxx.sqrt() * syy.sqrt()))
}

/// Split `values` at their median; return (pass rate of the ≥median half,
/// pass rate of the <median half). `None` when fewer than 2 points or the
/// split is degenerate (all values equal → no meaningful high/low).
fn median_split_pass(values: &[f64], passed: &[f64]) -> (Option<f64>, Option<f64>) {
    let n = values.len();
    if n < 2 {
        return (None, None);
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    };
    let mut high_pass = 0.0;
    let mut high_n = 0usize;
    let mut low_pass = 0.0;
    let mut low_n = 0usize;
    for i in 0..n {
        if values[i] >= median {
            high_pass += passed[i];
            high_n += 1;
        } else {
            low_pass += passed[i];
            low_n += 1;
        }
    }
    // Degenerate (all equal → everything lands in "high"): can't split.
    if high_n == 0 || low_n == 0 {
        return (None, None);
    }
    (
        Some(high_pass / high_n as f64),
        Some(low_pass / low_n as f64),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pr(label: &str, on: f64, off: f64, pon: bool, poff: bool) -> PairedResult {
        PairedResult {
            task_label: label.to_string(),
            score_on: on,
            score_off: off,
            passed_on: pon,
            passed_off: poff,
        }
    }

    #[test]
    fn empty_paired_is_inconclusive() {
        let s = aggregate_paired(&[]);
        assert_eq!(s.n, 0);
        assert_eq!(s.verdict, LiftVerdict::Inconclusive);
        assert_eq!(s.sign_test_p, 1.0);
    }

    #[test]
    fn clear_improvement_is_detected() {
        // 8 tasks, ON beats OFF in every one by a clear margin.
        let results: Vec<_> = (0..8)
            .map(|i| pr(&format!("t{i}"), 0.9, 0.5, true, false))
            .collect();
        let s = aggregate_paired(&results);
        assert!((s.mean_delta - 0.4).abs() < 1e-9);
        assert_eq!(s.wins, 8);
        assert_eq!(s.losses, 0);
        assert_eq!(s.pass_rate_on, 1.0);
        assert_eq!(s.pass_rate_off, 0.0);
        // 8/8 one-sided is p = 2 * 0.5^8 = 0.0078 < 0.10.
        assert!(s.sign_test_p < 0.05, "p={}", s.sign_test_p);
        assert_eq!(s.verdict, LiftVerdict::Improves);
    }

    #[test]
    fn clear_regression_is_detected() {
        let results: Vec<_> = (0..8)
            .map(|i| pr(&format!("t{i}"), 0.4, 0.9, false, true))
            .collect();
        let s = aggregate_paired(&results);
        assert!(s.mean_delta < 0.0);
        assert_eq!(s.wins, 0);
        assert_eq!(s.losses, 8);
        assert_eq!(s.verdict, LiftVerdict::Regresses);
    }

    #[test]
    fn small_noisy_effect_stays_inconclusive() {
        // Mixed wins/losses, tiny mean delta → not significant.
        let results = vec![
            pr("a", 0.8, 0.7, true, true),
            pr("b", 0.6, 0.7, true, true),
            pr("c", 0.9, 0.8, true, true),
            pr("d", 0.5, 0.6, false, true),
        ];
        let s = aggregate_paired(&results);
        assert_eq!(s.verdict, LiftVerdict::Inconclusive);
    }

    #[test]
    fn all_ties_give_p_one() {
        let results = vec![pr("a", 0.7, 0.7, true, true), pr("b", 1.0, 1.0, true, true)];
        let s = aggregate_paired(&results);
        assert_eq!(s.ties, 2);
        assert_eq!(s.wins, 0);
        assert_eq!(s.losses, 0);
        assert_eq!(s.sign_test_p, 1.0);
        assert_eq!(s.verdict, LiftVerdict::Inconclusive);
    }

    #[test]
    fn sign_test_matches_known_values() {
        // 5/5 split → p = 1.0 (perfectly balanced).
        assert!((two_sided_sign_test(5, 5) - 1.0).abs() < 1e-9);
        // 10/0 → p = 2 * 0.5^10 = 0.001953125.
        assert!((two_sided_sign_test(10, 0) - 0.001953125).abs() < 1e-9);
        // 0/0 → 1.0.
        assert_eq!(two_sided_sign_test(0, 0), 1.0);
        // 6/0 → 2 * 0.5^6 = 0.03125.
        assert!((two_sided_sign_test(6, 0) - 0.03125).abs() < 1e-9);
    }

    fn obs(fused: f64, count: i64, passed: Option<bool>, score: Option<f64>) -> ObservationalRow {
        ObservationalRow {
            mean_fused: fused,
            mem_count: count,
            judge_passed: passed,
            judge_score: score,
        }
    }

    #[test]
    fn observational_ignores_unlabeled() {
        let rows = vec![
            obs(0.9, 5, None, None),
            obs(0.8, 4, Some(true), Some(0.8)),
            obs(0.2, 1, Some(false), Some(0.3)),
        ];
        let r = analyze_observational(&rows);
        assert_eq!(r.n_labeled, 2);
        assert!((r.overall_pass_rate - 0.5).abs() < 1e-9);
    }

    #[test]
    fn observational_positive_correlation() {
        // High relevance → pass, low relevance → fail: strong positive corr.
        let rows = vec![
            obs(0.9, 6, Some(true), Some(0.9)),
            obs(0.85, 5, Some(true), Some(0.85)),
            obs(0.8, 5, Some(true), Some(0.8)),
            obs(0.2, 1, Some(false), Some(0.2)),
            obs(0.15, 1, Some(false), Some(0.25)),
            obs(0.1, 1, Some(false), Some(0.3)),
        ];
        let r = analyze_observational(&rows);
        assert_eq!(r.n_labeled, 6);
        let c = r.corr_relevance_pass.expect("corr computable");
        assert!(c > 0.8, "expected strong positive corr, got {c}");
        assert!(r.pass_rate_high_relevance.unwrap() > r.pass_rate_low_relevance.unwrap());
    }

    #[test]
    fn observational_zero_variance_corr_is_none() {
        // All same relevance → no variance → correlation undefined.
        let rows = vec![
            obs(0.5, 3, Some(true), Some(0.6)),
            obs(0.5, 3, Some(false), Some(0.4)),
        ];
        let r = analyze_observational(&rows);
        assert!(r.corr_relevance_pass.is_none());
    }
}

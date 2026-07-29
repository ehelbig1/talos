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
use talos_measurement::pearson_ci95;

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
    /// Newest SCORED judge verdict for the execution, if any.
    ///
    /// Abstentions (`judge_scores.not_applicable`) never reach here: the
    /// source lateral in `talos_memory::fetch_execution_memory_outcomes`
    /// filters them, so an execution whose only verdict was an abstention
    /// arrives with `judge_passed = None` and is dropped from the analyzable
    /// set below — an abstention is not an outcome label.
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
    /// 95% CI for `corr_relevance_pass` (Fisher z). `None` when the
    /// correlation is `None`, when `n_labeled < 4`, or when `|r| = 1`.
    ///
    /// APPROXIMATE: the Fisher transform assumes a bivariate-normal pair and
    /// this is a point-biserial (one variable is a 0/1 judge pass), so
    /// coverage degrades as the pass rate approaches 0 or 1. Read it as "could
    /// this be zero?", not as an exact bound — and never as causal.
    pub corr_relevance_pass_ci95: Option<[f64; 2]>,
    /// Correlation between memory count and judge pass. `None` as above.
    pub corr_count_pass: Option<f64>,
    /// 95% CI for `corr_count_pass`. Same caveats as
    /// `corr_relevance_pass_ci95`.
    pub corr_count_pass_ci95: Option<[f64; 2]>,
    /// Pass rate among the higher-relevance half (mean_fused ≥ median).
    pub pass_rate_high_relevance: Option<f64>,
    /// Pass rate among the lower-relevance half.
    pub pass_rate_low_relevance: Option<f64>,
    /// Size of the higher-relevance half — the denominator of
    /// `pass_rate_high_relevance`.
    ///
    /// Added 2026-07-28 (measurement envelope, S3). Without it a 1-of-1 half
    /// renders 100% identically to a 200-of-200 half, and the median split is
    /// exactly where a lopsided subgroup is likeliest (ties all land high).
    /// `n_high + n_low == n_labeled` whenever the split is non-degenerate.
    pub n_high: Option<usize>,
    /// Size of the lower-relevance half — the denominator of
    /// `pass_rate_low_relevance`.
    pub n_low: Option<usize>,
    /// Mean judge score across labeled executions (ignores rows w/o a score).
    pub mean_judge_score: Option<f64>,
    /// The DENOMINATOR of `mean_judge_score`: labeled executions that carry a
    /// numeric judge score.
    ///
    /// This is a silent subset of `n_labeled` — a judge can pass/fail without
    /// emitting a score — so the mean is over `n_scored`, not `n_labeled`.
    /// `n_labeled - n_scored` is the number of labeled executions with no
    /// score.
    pub n_scored: usize,
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
            corr_relevance_pass_ci95: None,
            corr_count_pass: None,
            corr_count_pass_ci95: None,
            pass_rate_high_relevance: None,
            pass_rate_low_relevance: None,
            n_high: None,
            n_low: None,
            mean_judge_score: None,
            n_scored: 0,
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

    // Median split on relevance → compare pass rates of the two halves, with
    // each half's size (S3: a subgroup rate without its denominator is the
    // same defect as the headline rate without n).
    let split = median_split_pass(&relevance, &passed);

    // Mean judge score over rows that carry a numeric score. `n_scored` is
    // that denominator — a silent subset of `n_labeled` until now.
    let scores: Vec<f64> = labeled.iter().filter_map(|r| r.judge_score).collect();
    let n_scored = scores.len();
    let mean_judge_score = if scores.is_empty() {
        None
    } else {
        Some(scores.iter().sum::<f64>() / n_scored as f64)
    };

    // Fisher-z intervals on the correlations. The n is the analyzable set —
    // both series are computed over exactly the `labeled` rows.
    let n_u = n as u64;
    ObservationalReport {
        n_labeled: n,
        overall_pass_rate,
        corr_relevance_pass_ci95: corr_relevance_pass.and_then(|r| pearson_ci95(r, n_u)),
        corr_relevance_pass,
        corr_count_pass_ci95: corr_count_pass.and_then(|r| pearson_ci95(r, n_u)),
        corr_count_pass,
        pass_rate_high_relevance: split.high_rate,
        pass_rate_low_relevance: split.low_rate,
        n_high: split.n_high,
        n_low: split.n_low,
        mean_judge_score,
        n_scored,
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

/// Result of the median split: each half's pass rate AND its size.
///
/// The sizes are the point of the struct — the tuple this replaced returned
/// two rates with no denominators, so a 1-row "high" half rendered 100%
/// exactly like a 200-row one. All four fields are `None`/`None` together when
/// the split does not happen.
#[derive(Clone, Copy, Debug, Default)]
struct MedianSplit {
    high_rate: Option<f64>,
    low_rate: Option<f64>,
    n_high: Option<usize>,
    n_low: Option<usize>,
}

/// Split `values` at their median; return each half's pass rate and size (the
/// ≥median half is "high"). All-`None` when fewer than 2 points or the split
/// is degenerate (all values equal → no meaningful high/low).
fn median_split_pass(values: &[f64], passed: &[f64]) -> MedianSplit {
    let n = values.len();
    if n < 2 {
        return MedianSplit::default();
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
        return MedianSplit::default();
    }
    MedianSplit {
        high_rate: Some(high_pass / high_n as f64),
        low_rate: Some(low_pass / low_n as f64),
        n_high: Some(high_n),
        n_low: Some(low_n),
    }
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

    /// An execution whose only judge verdict was an ABSTENTION must not
    /// enter the correlation. The exclusion is structural — the source
    /// lateral in `talos_memory::fetch_execution_memory_outcomes` filters
    /// `not_applicable` rows, so such an execution arrives here with
    /// `judge_passed: None` and is dropped by the `is_some` filter.
    ///
    /// This test pins the CONSEQUENCE of that contract: were the DB filter
    /// ever removed, an abstention would arrive as `Some(true)` with score
    /// 1.0 and silently inflate `overall_pass_rate` and the correlation.
    #[test]
    fn observational_drops_executions_whose_verdict_was_an_abstention() {
        // Two really-scored executions plus one whose newest verdict was an
        // abstention (→ no scored verdict → arrives unlabeled).
        let rows = vec![
            obs(0.9, 5, Some(true), Some(0.9)),
            obs(0.2, 1, Some(false), Some(0.2)),
            obs(0.95, 9, None, None), // abstained → unlabeled
        ];
        let r = analyze_observational(&rows);
        assert_eq!(r.n_labeled, 2, "the abstaining execution must not count");
        assert!((r.overall_pass_rate - 0.5).abs() < 1e-9);
        // Mean score is over the two scored rows only.
        assert!((r.mean_judge_score.unwrap() - 0.55).abs() < 1e-9);
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

    // ---- S3 (measurement envelope, 2026-07-28) --------------------------

    /// Every subgroup rate must carry its own denominator, and the two
    /// denominators must account for the whole analyzable set.
    #[test]
    fn subgroup_ns_are_present_and_sum_to_n_labeled() {
        let rows = vec![
            obs(0.9, 6, Some(true), Some(0.9)),
            obs(0.85, 5, Some(true), Some(0.85)),
            obs(0.8, 5, Some(true), Some(0.8)),
            obs(0.2, 1, Some(false), Some(0.2)),
            obs(0.15, 1, Some(false), Some(0.25)),
            obs(0.1, 1, Some(false), Some(0.3)),
        ];
        let r = analyze_observational(&rows);
        let (nh, nl) = (r.n_high.unwrap(), r.n_low.unwrap());
        assert_eq!(nh + nl, r.n_labeled, "the split must partition the set");
        assert_eq!((nh, nl), (3, 3));
        // A rate is only ever emitted with its n.
        assert_eq!(r.pass_rate_high_relevance.is_some(), r.n_high.is_some());
        assert_eq!(r.pass_rate_low_relevance.is_some(), r.n_low.is_some());
    }

    /// The lopsided case the median split actually produces: ties all land in
    /// the "high" half, so a 5/1 split renders two rates that look comparable
    /// unless the ns are visible.
    #[test]
    fn a_lopsided_split_shows_its_lopsidedness() {
        let rows = vec![
            obs(0.5, 1, Some(true), Some(0.9)),
            obs(0.5, 1, Some(true), Some(0.9)),
            obs(0.5, 1, Some(true), Some(0.9)),
            obs(0.5, 1, Some(false), Some(0.1)),
            obs(0.5, 1, Some(true), Some(0.9)),
            obs(0.1, 1, Some(false), Some(0.1)),
        ];
        let r = analyze_observational(&rows);
        assert_eq!((r.n_high, r.n_low), (Some(5), Some(1)));
        // The "low" half is ONE execution — a 0% pass rate there is one run.
        assert_eq!(r.pass_rate_low_relevance, Some(0.0));
        assert_eq!(r.n_low, Some(1));
    }

    /// A degenerate split emits neither rates nor ns — not zeroes.
    #[test]
    fn a_degenerate_split_emits_no_subgroup_numbers() {
        let rows = vec![
            obs(0.5, 3, Some(true), Some(0.6)),
            obs(0.5, 3, Some(false), Some(0.4)),
        ];
        let r = analyze_observational(&rows);
        assert!(r.pass_rate_high_relevance.is_none());
        assert!(r.n_high.is_none() && r.n_low.is_none());
        // …and the empty case, where nothing was measured at all.
        let empty = analyze_observational(&[]);
        assert_eq!(empty.n_labeled, 0);
        assert_eq!(empty.n_scored, 0);
        assert!(empty.n_high.is_none() && empty.n_low.is_none());
        assert!(empty.corr_relevance_pass_ci95.is_none());
    }

    /// `mean_judge_score`'s denominator was silent: labeled executions
    /// without a numeric score are excluded, so it is over `n_scored`.
    #[test]
    fn mean_judge_score_reports_its_own_denominator() {
        let rows = vec![
            obs(0.9, 5, Some(true), Some(1.0)),
            obs(0.8, 4, Some(true), None), // labeled, unscored
            obs(0.2, 1, Some(false), Some(0.0)),
            obs(0.1, 1, Some(false), None), // labeled, unscored
        ];
        let r = analyze_observational(&rows);
        assert_eq!(r.n_labeled, 4);
        assert_eq!(r.n_scored, 2, "only two rows carry a numeric score");
        assert_eq!(r.n_labeled - r.n_scored, 2, "the unscored delta is legible");
        assert!((r.mean_judge_score.unwrap() - 0.5).abs() < 1e-9);
        // No score anywhere → no mean, and n_scored says why.
        let none_scored = vec![
            obs(0.9, 5, Some(true), None),
            obs(0.1, 1, Some(false), None),
        ];
        let r2 = analyze_observational(&none_scored);
        assert_eq!(r2.n_scored, 0);
        assert!(r2.mean_judge_score.is_none());
    }

    /// A correlation with no interval is a number a reader will over-read.
    #[test]
    fn correlations_carry_an_interval_when_n_supports_one() {
        let rows: Vec<_> = (0..20)
            .map(|i| {
                let pass = i % 2 == 0;
                obs(
                    if pass { 0.8 } else { 0.2 },
                    if pass { 5 } else { 1 },
                    Some(pass),
                    Some(if pass { 0.9 } else { 0.1 }),
                )
            })
            .collect();
        let r = analyze_observational(&rows);
        // Perfect separation → r indistinguishable from 1, which has no
        // honest Fisher interval (tanh saturates; both ends land on 1.0).
        assert!(r.corr_relevance_pass.unwrap() > 0.999_999_999_999);
        assert!(
            r.corr_relevance_pass_ci95.is_none(),
            "|r| ≈ 1 must not claim a zero-width interval"
        );

        // A noisier set: correlation < 1, so the interval exists and brackets.
        let mut noisy = rows.clone();
        noisy[0] = obs(0.8, 5, Some(false), Some(0.1));
        noisy[1] = obs(0.2, 1, Some(true), Some(0.9));
        let r2 = analyze_observational(&noisy);
        let c = r2.corr_relevance_pass.unwrap();
        let [lo, hi] = r2.corr_relevance_pass_ci95.expect("n=20 supports a CI");
        assert!(lo < c && hi > c, "[{lo},{hi}] must bracket {c}");
        assert!(lo > -1.0 && hi < 1.0);
        assert!(r2.corr_count_pass_ci95.is_some());
    }

    /// Below the Fisher validity floor there is no interval — not a made-up
    /// one. (n_labeled = 2 or 3.)
    #[test]
    fn correlation_interval_is_absent_below_the_fisher_floor() {
        let rows = vec![
            obs(0.9, 5, Some(true), Some(0.9)),
            obs(0.5, 3, Some(true), Some(0.7)),
            obs(0.2, 1, Some(false), Some(0.2)),
        ];
        let r = analyze_observational(&rows);
        assert_eq!(r.n_labeled, 3);
        assert!(r.corr_relevance_pass.is_some(), "r itself is computable");
        assert!(
            r.corr_relevance_pass_ci95.is_none(),
            "n=3 is below the 1/sqrt(n-3) floor"
        );
    }

    /// The paired sibling is deliberately untouched by this change.
    #[test]
    fn eval_summary_shape_is_unchanged() {
        let s = aggregate_paired(&[]);
        let v = serde_json::to_value(&s).unwrap();
        // serde_json orders map keys; compare the SET, sorted.
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        let mut want = vec![
            "n",
            "mean_score_on",
            "mean_score_off",
            "mean_delta",
            "pass_rate_on",
            "pass_rate_off",
            "wins",
            "losses",
            "ties",
            "sign_test_p",
            "verdict",
        ];
        want.sort_unstable();
        assert_eq!(keys, want, "EvalSummary is out of scope for this change");
    }
}

//! The measurement envelope — one shape for "a number we measured".
//!
//! # Why this crate exists
//!
//! Three consecutive bugs (#580 → #588 → #589) all landed on ONE annotation
//! (a model-card gold-accuracy float) for the same reason: a bare `f64` in a
//! report carries no sample size, no population, no window and no version, so
//! every reader — human or model — supplies those from imagination. 1-for-1
//! renders identically to 400-for-400; an all-epochs aggregate renders
//! identically to a current-epoch one; a rate computed over a filtered subset
//! renders identically to one over the whole set.
//!
//! Before this crate the fix had been retrofitted PIECEMEAL, six times, each
//! invented locally:
//!
//! | Precedent | Where it lived | Replaced by |
//! |---|---|---|
//! | `wilson_interval_95` | `talos-operator-digest/src/lib.rs` (2026-07-26) | [`wilson_interval_95`] (MOVED here verbatim; the digest re-exports it) |
//! | `min_n_for_target` (inline) | `talos-mcp-handlers/src/analytics.rs` SLA handler (MCP-4) | [`min_n_for_rate_target`] |
//! | `population_note` hand-copy ×2 | `talos-operator-digest/src/lib.rs`, `talos-engine/src/assistant_report_reader.rs` | [`JUDGE_SCORE_POPULATION_NOTE`] |
//! | three different n-gating shapes | `MIN_GOLD_FOR_BAND_VERDICT`, `MIN_JUDGE_RUNS`, `min_shadow_total` | [`Sufficiency`] (the SHAPE only — each policy keeps its own floor) |
//! | `LiftVerdict::Inconclusive` | `talos-evaluation/src/stats.rs` | (kept; the same doctrine, already rigorous) |
//! | `shadow_epoch` / `gold_promoted_is_stale` | `talos-ml` | (kept; population/window disambiguation) |
//!
//! # The doctrine (read before adding a field)
//!
//! **A missing field renders as "not measured", NEVER as a defaulted `0.0`.**
//! Every optional field on [`Measurement`] is `Option` and is
//! `skip_serializing_if`-omitted, so a consumer can distinguish "we did not
//! compute a confidence interval" from "the interval is [0, 0]". This is the
//! same contract `build_reliability_section` already enforces in the operator
//! digest: a check that did not run must not emit a verdict.
//!
//! Corollary: a rate over `n = 0` has no value. [`Measurement::rate`] and
//! [`Measurement::from_fraction`] return `None` there rather than emitting a
//! healthy-looking `0.0` or a `NaN`.
//!
//! # Dependency posture
//!
//! Leaf crate: `serde` + `serde_json` only, no I/O, pure math. Nothing in here
//! may grow a dependency on a repository, service or engine crate — the whole
//! point is that any layer can annotate a number without inverting the graph.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Population disclosure for every judge-score aggregate we render.
///
/// Consolidates two byte-identical hand-copies (D5): the operator digest's
/// per-workflow judge block and the assistant report reader's `judge_scores`
/// block. Both now re-import this constant, so the sentence can never drift
/// away from the `FILTER (WHERE NOT not_applicable)` it describes.
///
/// (The `population_note` in `talos-mcp-handlers/src/ml.rs`'s dataset-dedupe
/// output is a DIFFERENT sentence about a different population — embedding
/// coverage within a dataset — and is deliberately not consolidated here.)
pub const JUDGE_SCORE_POPULATION_NOTE: &str =
    "runs/avg_score/pass_rate/worst_score cover SCORED verdicts only; na_runs counts runs \
     where the judge reported nothing to judge and which are excluded from every score above";

/// The 95% two-sided standard-normal critical value.
///
/// Kept at the digest's original literal precision so the moved
/// [`wilson_interval_95`] is bit-identical to the pre-move implementation.
const Z_95: f64 = 1.959_963_984_540_054;

/// A measured number plus everything a reader needs in order not to
/// over-read it.
///
/// Only `value` and `n` are mandatory: a number with no sample size is the
/// defect this type exists to prevent. Everything else is `Option` and is
/// omitted from JSON when absent — see the doctrine in the crate docs.
///
/// The serialized shape is additive-friendly: adding a field here can never
/// change the JSON an existing producer emits, because absent fields are
/// skipped rather than nulled.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Measurement {
    /// The point estimate. For a rate this is a fraction in `[0, 1]`, not a
    /// percentage — percentage formatting is a rendering decision.
    pub value: f64,
    /// The number of observations the estimate is computed over. This is the
    /// field whose absence caused #580/#588/#589; it is deliberately not
    /// optional.
    pub n: u64,
    /// 95% confidence interval `[lo, hi]` when one was computed.
    ///
    /// An INTERVAL, not a bound: it describes the sampling uncertainty of
    /// this estimate under its stated model (Wilson for rates, Fisher z for
    /// correlations), and says nothing about the population being stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci95: Option<[f64; 2]>,
    /// Which rows the number covers, in OUR taxonomy — e.g. "executions
    /// started in the last 30 days, any status". Never request-derived text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub population: Option<String>,
    /// The time or era bound — e.g. "epoch 3", "lifetime (all epochs)",
    /// "trailing 30 days".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
    /// Which version of the thing being measured produced it (model version,
    /// artifact sha, build sha).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
    /// When the measurement was taken (RFC 3339). A number with no timestamp
    /// cannot be told apart from a stale one — see the `requires_fresh`
    /// input-freshness contracts for the same failure mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_at: Option<String>,
}

impl Measurement {
    /// A raw measured value over `n` observations, with no interval.
    ///
    /// Use [`Self::rate`] or [`Self::from_fraction`] for proportions — they
    /// fill in the Wilson interval for you.
    #[must_use]
    pub fn new(value: f64, n: u64) -> Self {
        Self {
            value,
            n,
            ci95: None,
            population: None,
            window: None,
            source_version: None,
            measured_at: None,
        }
    }

    /// A rate from raw counts, with the Wilson 95% interval filled in.
    ///
    /// `None` when `n == 0` (there is no rate to report — emitting `0.0`
    /// would render "never ran" as "always failed") or when
    /// `successes > n` (a nonsense input we refuse rather than clamp).
    #[must_use]
    pub fn rate(successes: u64, n: u64) -> Option<Self> {
        if n == 0 || successes > n {
            return None;
        }
        Self::from_fraction(successes as f64 / n as f64, n)
    }

    /// A rate the caller already has as a fraction (e.g. computed in SQL),
    /// with the Wilson 95% interval filled in.
    ///
    /// `None` when `n == 0` or the fraction is not a finite value in
    /// `[0, 1]`.
    #[must_use]
    pub fn from_fraction(fraction: f64, n: u64) -> Option<Self> {
        let ci = wilson_interval_95(fraction, i64::try_from(n).ok()?)?;
        let mut m = Self::new(fraction, n);
        m.ci95 = Some([ci.0, ci.1]);
        Some(m)
    }

    /// Set the population disclosure. Use OUR taxonomy, and make it match the
    /// query that actually produced the number.
    #[must_use]
    pub fn with_population(mut self, population: impl Into<String>) -> Self {
        self.population = Some(population.into());
        self
    }

    /// Set the time/era bound.
    #[must_use]
    pub fn with_window(mut self, window: impl Into<String>) -> Self {
        self.window = Some(window.into());
        self
    }

    /// Set the version of the measured artifact.
    #[must_use]
    pub fn with_source_version(mut self, version: impl Into<String>) -> Self {
        self.source_version = Some(version.into());
        self
    }

    /// Set the measurement timestamp (RFC 3339).
    #[must_use]
    pub fn with_measured_at(mut self, at: impl Into<String>) -> Self {
        self.measured_at = Some(at.into());
        self
    }

    /// Judge this measurement's sample size against a caller-supplied floor.
    ///
    /// The floor stays with the POLICY — this crate deliberately does not own
    /// one. See [`Sufficiency`].
    #[must_use]
    pub fn sufficiency(&self, floor: u64) -> Sufficiency {
        Sufficiency::judge(self.n, floor)
    }
}

/// Whether a sample is big enough for the verdict a caller wants to draw.
///
/// The three existing policies keep their own floors — `MIN_GOLD_FOR_BAND_VERDICT`
/// (40) in the operator digest, the judge-signal minimum, `min_shadow_total`
/// in the ML lifecycle — because they are legitimately different questions.
/// Only the SHAPE unifies, so a reader learns one vocabulary instead of three.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "verdict")]
pub enum Sufficiency {
    /// `n >= floor`.
    Sufficient,
    /// `n < floor` — the number is real, but a verdict drawn from it is not.
    Insufficient { n: u64, floor: u64 },
}

impl Sufficiency {
    /// Compare a sample size against a policy floor.
    ///
    /// A floor of `0` means the policy has no opinion — always `Sufficient`.
    #[must_use]
    pub fn judge(n: u64, floor: u64) -> Self {
        if n >= floor {
            Self::Sufficient
        } else {
            Self::Insufficient { n, floor }
        }
    }

    /// `true` when the sample clears the floor.
    #[must_use]
    pub fn is_sufficient(&self) -> bool {
        matches!(self, Self::Sufficient)
    }

    /// Stable machine-readable label for JSON surfaces that want a plain
    /// string rather than the tagged enum.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Sufficient => "sufficient",
            Self::Insufficient { .. } => "insufficient",
        }
    }
}

impl fmt::Display for Sufficiency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sufficient => write!(f, "sufficient"),
            Self::Insufficient { n, floor } => {
                write!(f, "insufficient (n={n}, need {floor})")
            }
        }
    }
}

/// Wilson score interval (95%) for a proportion — the standard small-sample
/// interval, and correct where the normal approximation is not: it never leaves
/// [0, 1] and stays sane at 0 or 1 successes, both of which occur here (gold
/// `archive` recall was a literal 0/16 for weeks).
///
/// MOVED from `talos-operator-digest/src/lib.rs` (2026-07-28) VERBATIM — the
/// arithmetic, the constant's precision and the operation order are unchanged
/// so results are bit-identical to the pre-move implementation. The digest
/// re-exports this symbol; `wilson_pins_are_bit_identical_to_the_pre_move_digest`
/// pins the exact f64 outputs.
///
/// `None` (never `NaN`, never a defaulted zero-width interval) when `n <= 0`
/// or `accuracy` is not a finite value in `[0, 1]`.
#[must_use]
pub fn wilson_interval_95(accuracy: f64, n: i64) -> Option<(f64, f64)> {
    if n <= 0 || !accuracy.is_finite() || !(0.0..=1.0).contains(&accuracy) {
        return None;
    }
    const Z: f64 = Z_95;
    let n = n as f64;
    let denom = 1.0 + Z * Z / n;
    let centre = accuracy + Z * Z / (2.0 * n);
    let margin = Z * ((accuracy * (1.0 - accuracy) / n) + (Z * Z / (4.0 * n * n))).sqrt();
    Some((
        ((centre - margin) / denom).clamp(0.0, 1.0),
        ((centre + margin) / denom).clamp(0.0, 1.0),
    ))
}

/// Smallest sample size at which a `target` success rate is distinguishable
/// from "one bad run".
///
/// The smallest non-zero failure rate observable in `n` trials is `1/n`, so a
/// target of `t` only becomes meetable-and-measurable once `n >= 1/(1 - t)`:
/// `t = 0.95 → 20`, `t = 0.99 → 100`, `t = 0.999 → 1000`. Below that, a single
/// failure puts the observed rate under the target no matter how good the
/// system is, and the resulting "compliance failure" is non-actionable.
///
/// `target` is a FRACTION in `(0, 1)`, not a percentage. `None` outside that
/// open interval (a 0% or 100% target has no such threshold) — the callers
/// that previously used `0` as the "no threshold" sentinel now match on `None`.
///
/// Lifted from the inline MCP-4 math in
/// `talos-mcp-handlers/src/analytics.rs` (`handle_get_workflow_sla_report`),
/// which re-imports it.
#[must_use]
pub fn min_n_for_rate_target(target: f64) -> Option<u64> {
    if !target.is_finite() || target <= 0.0 || target >= 1.0 {
        return None;
    }
    let n = (1.0 / (1.0 - target)).ceil();
    if n.is_finite() && n >= 1.0 {
        Some(n as u64)
    } else {
        None
    }
}

/// How close to ±1 a correlation may be before [`pearson_ci95`] refuses to
/// report an interval for it.
///
/// Chosen so that ordinary strong correlations (`r = 0.999` and below) keep
/// their interval, while the numerically-perfect separation a point-biserial
/// produces (`r` within ~1e-15 of 1) is refused rather than rendered as a
/// fifteen-digit near-certainty.
pub const NEAR_PERFECT_R_TOLERANCE: f64 = 1e-9;

/// 95% confidence interval for a Pearson correlation via the Fisher
/// z-transform: `z = atanh(r)`, `se = 1/sqrt(n - 3)`, then back-transform
/// `tanh(z ± 1.96·se)`.
///
/// # Honest caveats (read these before quoting the interval)
///
/// * The Fisher transform's normality of `z` is exact only for a BIVARIATE
///   NORMAL pair. Our headline use is a point-biserial correlation (continuous
///   relevance vs. a 0/1 judge pass), where one variable is Bernoulli, so the
///   interval is an approximation whose coverage degrades as the pass rate
///   approaches 0 or 1. Treat it as an order-of-magnitude honesty signal
///   ("could this be zero?"), not an exact bound.
/// * The standard error `1/sqrt(n-3)` requires `n > 3`; `n < 4` returns `None`
///   rather than a made-up interval.
/// * `|r| >= 1 - `[`NEAR_PERFECT_R_TOLERANCE`] returns `None`. `atanh(±1)` is
///   infinite, and just short of it the transform is numerically degenerate:
///   a perfectly-separating point-biserial produces `r = 0.999_999_999_999_999_4`
///   (not exactly 1), whose Fisher interval is
///   `[0.999_999_999_999_998_4, 0.999_999_999_999_999_8]` — fifteen digits of
///   spurious precision that read as a proof of certainty from what is
///   usually a handful of cleanly-split rows. Refusing is the honest answer:
///   perfect separation means the interval is uninformative, not that the
///   correlation is certain.
/// * Observational: an interval excluding zero means "not explained by
///   sampling noise", not "causal".
#[must_use]
pub fn pearson_ci95(r: f64, n: u64) -> Option<[f64; 2]> {
    if !r.is_finite() || r.abs() >= 1.0 - NEAR_PERFECT_R_TOLERANCE || n < 4 {
        return None;
    }
    let z = r.atanh();
    let se = 1.0 / ((n - 3) as f64).sqrt();
    let lo = (z - Z_95 * se).tanh();
    let hi = (z + Z_95 * se).tanh();
    // A zero-width interval claims certainty. It happens for r close enough
    // to ±1 that tanh saturates at the f64 level — refuse rather than render
    // "[1.0, 1.0]", which reads as a proof.
    if lo.is_finite() && hi.is_finite() && hi > lo {
        Some([lo, hi])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Wilson: bit-identical pins against the pre-move digest ----------
    //
    // These literals were computed from the ORIGINAL
    // talos-operator-digest::wilson_interval_95 before the move. Any change
    // to the constant's precision or to the order of operations moves the
    // last ULP and fails here.
    #[test]
    fn wilson_pins_are_bit_identical_to_the_pre_move_digest() {
        let cases: &[(f64, i64, f64, f64)] = &[
            (0.4857, 35, 0.329_929_602_948_868_2, 0.644_298_965_431_609_8),
            (0.0, 16, 0.0, 0.193_607_680_534_436_5),
            (1.0, 5, 0.565_517_535_216_825_2, 1.0),
            (0.5, 35, 0.342_757_359_214_807_77, 0.657_242_640_785_192_2),
            (0.5, 350, 0.447_902_877_439_325_4, 0.552_097_122_560_674_7),
            (
                0.093_75,
                32,
                0.032_401_551_298_366_2,
                0.242_181_547_283_878_64,
            ),
            (0.8, 100, 0.711_170_834_406_841_1, 0.866_633_066_668_967_4),
        ];
        for &(acc, n, lo_want, hi_want) in cases {
            let (lo, hi) = wilson_interval_95(acc, n).expect("finite in-range input");
            assert_eq!(
                lo.to_bits(),
                lo_want.to_bits(),
                "lo drifted for ({acc}, {n}): got {lo}, want {lo_want}"
            );
            assert_eq!(
                hi.to_bits(),
                hi_want.to_bits(),
                "hi drifted for ({acc}, {n}): got {hi}, want {hi_want}"
            );
        }
    }

    #[test]
    fn wilson_edges_k_zero_k_n_and_n_zero() {
        // k = 0: lower bound pinned at 0, upper bound emphatically NOT 0 —
        // "0 for 16" is not "zero forever".
        let (lo, hi) = wilson_interval_95(0.0, 16).unwrap();
        assert_eq!(lo, 0.0);
        assert!(hi > 0.0 && hi < 0.3, "0/16 upper bound was {hi}");
        // k = n: symmetric.
        let (lo, hi) = wilson_interval_95(1.0, 5).unwrap();
        assert_eq!(hi, 1.0);
        assert!(lo < 1.0 && lo > 0.5, "5/5 lower bound was {lo}");
        // n = 0 (and negative): REFUSAL, not NaN and not a zero-width
        // interval — there is no interval for a sample that does not exist.
        assert!(wilson_interval_95(0.5, 0).is_none());
        assert!(wilson_interval_95(0.0, 0).is_none());
        assert!(wilson_interval_95(0.5, -3).is_none());
        // Nonsense point estimates are refused rather than clamped.
        assert!(wilson_interval_95(f64::NAN, 10).is_none());
        assert!(wilson_interval_95(f64::INFINITY, 10).is_none());
        assert!(wilson_interval_95(1.5, 10).is_none());
        assert!(wilson_interval_95(-0.1, 10).is_none());
    }

    #[test]
    fn wilson_narrows_with_more_observations() {
        let (wlo, whi) = wilson_interval_95(0.5, 35).unwrap();
        let (nlo, nhi) = wilson_interval_95(0.5, 350).unwrap();
        assert!((nhi - nlo) < (whi - wlo));
    }

    // ---- Measurement serde shape ----------------------------------------

    #[test]
    fn measurement_serde_omits_unmeasured_fields_rather_than_nulling_them() {
        let m = Measurement::new(0.5, 4);
        let v = serde_json::to_value(&m).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 2, "only value + n should serialize: {v}");
        assert!(obj.contains_key("value") && obj.contains_key("n"));
        for absent in [
            "ci95",
            "population",
            "window",
            "source_version",
            "measured_at",
        ] {
            assert!(
                !obj.contains_key(absent),
                "{absent} must be OMITTED, not null — a null reads as 0.0 to half the consumers"
            );
        }
        // Round-trips through the omitted form.
        let back: Measurement = serde_json::from_value(v).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn measurement_builders_are_additive() {
        let m = Measurement::rate(9, 10)
            .unwrap()
            .with_population("executions started in the last 30 days")
            .with_window("trailing 30 days")
            .with_source_version("v7")
            .with_measured_at("2026-07-28T00:00:00Z");
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["value"], 0.9);
        assert_eq!(v["n"], 10);
        assert!(v["ci95"].is_array(), "rate() must fill the Wilson interval");
        assert_eq!(v["window"], "trailing 30 days");
        assert_eq!(v["source_version"], "v7");
        assert_eq!(v["measured_at"], "2026-07-28T00:00:00Z");
        let lo = v["ci95"][0].as_f64().unwrap();
        let hi = v["ci95"][1].as_f64().unwrap();
        assert!(lo < 0.9 && hi > 0.9 && hi <= 1.0);
    }

    #[test]
    fn rate_refuses_the_zero_denominator_and_nonsense_counts() {
        // The whole point: n = 0 must NOT render as a healthy-looking 0.0.
        assert!(Measurement::rate(0, 0).is_none());
        assert!(Measurement::from_fraction(0.0, 0).is_none());
        // successes > n is a bug upstream; refuse rather than clamp to 1.0.
        assert!(Measurement::rate(5, 4).is_none());
        // Non-finite / out-of-range fractions are refused too.
        assert!(Measurement::from_fraction(f64::NAN, 10).is_none());
        assert!(Measurement::from_fraction(1.2, 10).is_none());
        // A real zero rate over a real sample IS reportable.
        let m = Measurement::rate(0, 16).unwrap();
        assert_eq!(m.value, 0.0);
        assert_eq!(m.n, 16);
        assert!(m.ci95.unwrap()[1] > 0.0);
    }

    // ---- Sufficiency -----------------------------------------------------

    #[test]
    fn sufficiency_carries_the_floor_it_was_judged_against() {
        let s = Sufficiency::judge(12, 20);
        assert!(!s.is_sufficient());
        assert_eq!(s, Sufficiency::Insufficient { n: 12, floor: 20 });
        assert_eq!(s.label(), "insufficient");
        assert_eq!(s.to_string(), "insufficient (n=12, need 20)");
        let s = Sufficiency::judge(20, 20);
        assert!(s.is_sufficient());
        assert_eq!(s.label(), "sufficient");
        assert_eq!(s.to_string(), "sufficient");
        // A floor of 0 = the policy has no opinion.
        assert!(Sufficiency::judge(0, 0).is_sufficient());
        // Reachable from a Measurement.
        assert!(!Measurement::new(1.0, 1).sufficiency(20).is_sufficient());
    }

    // ---- min_n_for_rate_target ------------------------------------------

    #[test]
    fn min_n_pins_match_the_existing_analytics_expectations() {
        // The three worked examples documented at the MCP-4 call site.
        assert_eq!(min_n_for_rate_target(0.99), Some(100));
        assert_eq!(min_n_for_rate_target(0.95), Some(20));
        assert_eq!(min_n_for_rate_target(0.999), Some(1000));
        // The old inline code returned the 0 sentinel here; we return None.
        assert_eq!(min_n_for_rate_target(1.0), None);
        assert_eq!(min_n_for_rate_target(0.0), None);
        assert_eq!(min_n_for_rate_target(-0.5), None);
        assert_eq!(min_n_for_rate_target(1.5), None);
        assert_eq!(min_n_for_rate_target(f64::NAN), None);
    }

    // ---- pearson_ci95 ----------------------------------------------------

    #[test]
    fn pearson_ci95_matches_textbook_fisher_z_values() {
        // r = 0.5, n = 30: the standard worked example — z = atanh(0.5) =
        // 0.549306, se = 1/sqrt(27) = 0.192450, so the interval is
        // tanh(0.549306 ± 1.959964·0.192450) = (0.170431, 0.728959).
        let [lo, hi] = pearson_ci95(0.5, 30).unwrap();
        assert!((lo - 0.170_431_365).abs() < 1e-9, "lo={lo}");
        assert!((hi - 0.728_958_556).abs() < 1e-9, "hi={hi}");
        // The interval brackets the estimate and stays inside [-1, 1].
        assert!(lo < 0.5 && hi > 0.5 && lo > -1.0 && hi < 1.0);
        // Symmetric in sign.
        let [nlo, nhi] = pearson_ci95(-0.5, 30).unwrap();
        assert!((nlo + hi).abs() < 1e-12 && (nhi + lo).abs() < 1e-12);
        // r = 0 is centred on zero.
        let [zlo, zhi] = pearson_ci95(0.0, 103).unwrap();
        assert!((zlo + zhi).abs() < 1e-12);
        // More data narrows it.
        let [wlo, whi] = pearson_ci95(0.5, 30).unwrap();
        let [tlo, thi] = pearson_ci95(0.5, 300).unwrap();
        assert!((thi - tlo) < (whi - wlo));
    }

    #[test]
    fn pearson_ci95_refuses_the_degenerate_cases() {
        // n < 4: the Fisher standard error 1/sqrt(n-3) is undefined or
        // infinite. No interval, not a fabricated one.
        for n in 0..4u64 {
            assert!(pearson_ci95(0.5, n).is_none(), "n={n} must refuse");
        }
        assert!(pearson_ci95(0.5, 4).is_some(), "n=4 is the first valid n");
        // |r| = 1 would back-transform to a zero-width [1,1] interval that
        // reads as perfect certainty. Refuse.
        assert!(pearson_ci95(1.0, 100).is_none());
        assert!(pearson_ci95(-1.0, 100).is_none());
        // …and r merely INDISTINGUISHABLE from 1: the value a perfectly
        // separating point-biserial actually produces. Its Fisher interval is
        // fifteen digits of spurious precision, so it is refused too.
        assert!(pearson_ci95(0.999_999_999_999_999_4, 20).is_none());
        assert!(pearson_ci95(-0.999_999_999_999_999_4, 20).is_none());
        // An ordinary strong correlation keeps its interval, and the interval
        // has visible width — the tolerance must not swallow real data.
        let [lo, hi] = pearson_ci95(0.999, 20).expect("r=0.999 is reportable");
        assert!(hi - lo > 1e-4, "[{lo},{hi}] collapsed");
        assert!(lo < 0.999 && hi > 0.999);
        assert!(pearson_ci95(1.5, 100).is_none());
        assert!(pearson_ci95(f64::NAN, 100).is_none());
        // n = 4 is maximally wide — nearly the whole range.
        let [lo, hi] = pearson_ci95(0.5, 4).unwrap();
        assert!(lo < -0.8 && hi > 0.9, "n=4 interval was [{lo},{hi}]");
    }

    // ---- The consolidated population note --------------------------------

    #[test]
    fn judge_population_note_states_both_populations() {
        assert!(JUDGE_SCORE_POPULATION_NOTE.contains("SCORED"));
        assert!(JUDGE_SCORE_POPULATION_NOTE.contains("na_runs"));
        assert!(JUDGE_SCORE_POPULATION_NOTE.contains("excluded from every score above"));
    }
}

//! The RustSec advisory database's age: ONE home (2026-09-22).
//!
//! `cargo audit --no-fetch --db /opt/talos-advisory-db` runs against a copy
//! baked into the image at build time, so its advisory set is frozen until the
//! image is rebuilt. [`crate::check_advisory_db_age`] warns at
//! [`ADVISORY_DB_WARN_AGE_DAYS`] and, in production, REFUSES every Rust compile
//! and audit at [`advisory_db_max_age_days`] (default 90).
//!
//! Until this module existed the age was computed TWICE — inline in the gate
//! and again in a helper that "mirrors" it for the compile-provenance log —
//! and only when somebody compiled. Measured 2026-09-22 on the reference
//! deployment: the controller's copy dated 2026-07-09, i.e. 75 of 90 days,
//! and no series counted down to the day the gate would start refusing (the
//! Vault KEK token's shape before package BA). The age computation, the
//! limit, the verdict and the gate's decision each live here once; the
//! controller samples the age hourly through [`sample_and_publish_advisory_db_age`].
//!
//! **Stated limit.** The controller image and the builder image each bake
//! their own copy. The gate stats the CONTROLLER's; in container mode
//! `cargo audit` reads the BUILDER's (2026-07-09 vs 2026-07-07 on the
//! reference deployment). Only the controller's copy is sampled — it is the
//! one the gate consults — and the `copy` label says so.

use std::io;
use std::time::{Duration, SystemTime};

use talos_metrics::{AdvisoryDbCopy, AdvisoryDbSampleOutcome, TalosMetrics};

/// Age at which the gate starts warning. `TalosAdvisoryDbAging` fires at the
/// same number (pinned by `alerts_read_the_gates_own_thresholds`).
pub const ADVISORY_DB_WARN_AGE_DAYS: u64 = 30;
/// The fail-closed limit when [`ADVISORY_DB_MAX_AGE_ENV`] is unset or invalid.
pub const ADVISORY_DB_DEFAULT_MAX_AGE_DAYS: u64 = 90;
/// Cadence of the controller's age sampler. The age moves once a day, and a
/// sample is a few hundred `stat` calls (0.04 s on the reference deployment).
pub const ADVISORY_DB_AGE_SAMPLE_INTERVAL_SECS: u64 = 3600;

/// Why the database could not be dated. Neither is "fresh": the gate logs
/// and lets `cargo audit` surface the missing-DB error itself, the sampler
/// counts it as `unreadable`.
#[derive(Debug)]
pub enum AdvisoryDbAgeError {
    /// The path or its mtime could not be read.
    Unreadable(io::Error),
    /// The freshest signal is later than the clock — a clock behind the
    /// build, or a copied file with a future mtime.
    FutureDated,
}

impl std::fmt::Display for AdvisoryDbAgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(e) => write!(f, "advisory database unreadable: {e}"),
            Self::FutureDated => write!(f, "advisory database is dated in the future"),
        }
    }
}

impl std::error::Error for AdvisoryDbAgeError {}

/// Age of the baked advisory database in whole days.
///
/// The freshest of three filesystem signals wins, so each can independently
/// bound staleness (wasm-security-review, 2026-05-22): the directory mtime
/// (a `touch` refreshes it without any content change, so it is never
/// trusted alone), the `.git/refs/heads/main|master` mtime (written by every
/// `git fetch`, so it dates the upstream sync of a cloned advisory-db), and
/// the newest entry directly under `crates/` (a per-crate directory's mtime
/// moves whenever one of its advisories is added — depth 1 only, bounded at
/// 20 000 entries; the reference copy has 812).
pub fn advisory_db_age_days(db_path: &str) -> Result<u64, AdvisoryDbAgeError> {
    let meta = std::fs::metadata(db_path).map_err(AdvisoryDbAgeError::Unreadable)?;
    let mut freshest = meta.modified().map_err(AdvisoryDbAgeError::Unreadable)?;
    for ref_name in ["main", "master"] {
        let ref_path = format!("{db_path}/.git/refs/heads/{ref_name}");
        if let Ok(meta) = std::fs::metadata(&ref_path) {
            if let Ok(t) = meta.modified() {
                if t > freshest {
                    freshest = t;
                }
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(format!("{db_path}/crates")) {
        for entry in rd.flatten().take(20_000) {
            if let Ok(meta) = entry.metadata() {
                if let Ok(t) = meta.modified() {
                    if t > freshest {
                        freshest = t;
                    }
                }
            }
        }
    }
    let age = SystemTime::now()
        .duration_since(freshest)
        .map_err(|_| AdvisoryDbAgeError::FutureDated)?;
    Ok(age.as_secs() / 86_400)
}

/// The fail-closed limit: `TALOS_ADVISORY_DB_MAX_AGE_DAYS` as a positive
/// integer (whitespace-trimmed), else [`ADVISORY_DB_DEFAULT_MAX_AGE_DAYS`].
/// `=0` is not "never expire" — it is unset. The literal stays inline so
/// structural check 89 can see the reader.
#[must_use]
pub fn advisory_db_max_age_days() -> u64 {
    std::env::var("TALOS_ADVISORY_DB_MAX_AGE_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(ADVISORY_DB_DEFAULT_MAX_AGE_DAYS)
}

/// What an age says about the database, independent of the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryDbVerdict {
    /// Younger than the warn threshold.
    Fresh,
    /// At or past the warn threshold, under the limit.
    Aging,
    /// At or past the limit. Wins over `Aging` when the limit is set at or
    /// below the warn threshold.
    Expired,
}

#[must_use]
pub fn advisory_db_verdict(age_days: u64, max_age_days: u64) -> AdvisoryDbVerdict {
    if age_days >= max_age_days {
        AdvisoryDbVerdict::Expired
    } else if age_days >= ADVISORY_DB_WARN_AGE_DAYS {
        AdvisoryDbVerdict::Aging
    } else {
        AdvisoryDbVerdict::Fresh
    }
}

/// What the compile gate does with a measured age. Pure, so the production
/// arm is tested without touching `RUST_ENV`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisoryDbGateOutcome {
    /// Compile proceeds silently.
    Pass,
    /// Compile proceeds; the gate warns that the snapshot is aging.
    WarnAging,
    /// Expired, but this is not production: compile proceeds with a warning.
    WarnExpiredUnenforced,
    /// Expired in production: the compile is refused.
    Refuse,
}

#[must_use]
pub fn advisory_db_gate_outcome(
    age_days: u64,
    max_age_days: u64,
    production: bool,
) -> AdvisoryDbGateOutcome {
    match (advisory_db_verdict(age_days, max_age_days), production) {
        (AdvisoryDbVerdict::Expired, true) => AdvisoryDbGateOutcome::Refuse,
        (AdvisoryDbVerdict::Expired, false) => AdvisoryDbGateOutcome::WarnExpiredUnenforced,
        (AdvisoryDbVerdict::Aging, _) => AdvisoryDbGateOutcome::WarnAging,
        (AdvisoryDbVerdict::Fresh, _) => AdvisoryDbGateOutcome::Pass,
    }
}

/// One age sample of one baked copy, with the limit the gate would apply.
#[derive(Debug)]
pub struct AdvisoryDbSample {
    pub copy: AdvisoryDbCopy,
    pub age_days: Result<u64, AdvisoryDbAgeError>,
    pub max_age_days: u64,
    /// Whether an expired copy REFUSES compilation on this controller.
    pub enforced: bool,
}

/// Sample the copy at `db_path` under an explicit limit and posture.
#[must_use]
pub fn sample_advisory_db_with(
    db_path: &str,
    max_age_days: u64,
    enforced: bool,
) -> AdvisoryDbSample {
    AdvisoryDbSample {
        copy: AdvisoryDbCopy::Controller,
        age_days: advisory_db_age_days(db_path),
        max_age_days,
        enforced,
    }
}

/// Sample the controller's baked copy under the limit and posture the gate
/// itself resolves.
#[must_use]
pub fn sample_advisory_db() -> AdvisoryDbSample {
    sample_advisory_db_with(
        crate::container::ADVISORY_DB_PATH,
        advisory_db_max_age_days(),
        talos_config::is_production(),
    )
}

/// Publish a sample: the limit and posture always; the age ONLY when it was
/// measured, so an unreadable sample leaves the last reading standing and is
/// visible on the `unreadable` outcome instead of as a fresh-looking zero.
pub fn publish_advisory_db_sample(metrics: &TalosMetrics, sample: &AdvisoryDbSample) {
    talos_metrics::publish_advisory_db_limits_on(
        metrics,
        sample.copy,
        sample.max_age_days,
        sample.enforced,
    );
    match &sample.age_days {
        Ok(age) => {
            talos_metrics::publish_advisory_db_age_on(metrics, sample.copy, *age);
            talos_metrics::record_advisory_db_sample_on(
                metrics,
                sample.copy,
                AdvisoryDbSampleOutcome::Measured,
            );
        }
        Err(_) => talos_metrics::record_advisory_db_sample_on(
            metrics,
            sample.copy,
            AdvisoryDbSampleOutcome::Unreadable,
        ),
    }
}

/// One sampler tick: sample the controller's copy, publish it to `metrics`
/// when there is a registry, and log the reading. INFO on a measured sample
/// (24 lines a day — the series is the signal, not the log); WARN on an
/// unreadable one, because `cargo audit --no-fetch` fails in every
/// environment while the database cannot be read.
pub fn sample_and_publish_advisory_db_age(metrics: Option<&TalosMetrics>) -> AdvisoryDbSample {
    let sample = sample_advisory_db();
    if let Some(m) = metrics {
        publish_advisory_db_sample(m, &sample);
    }
    match &sample.age_days {
        Ok(age) => tracing::info!(
            target: "talos_compilation",
            event_kind = "advisory_db_age_sampled",
            copy = sample.copy.as_str(),
            age_days = age,
            max_age_days = sample.max_age_days,
            enforced = sample.enforced,
            verdict = ?advisory_db_verdict(*age, sample.max_age_days),
            "Baked RustSec advisory database age sampled"
        ),
        Err(e) => tracing::warn!(
            target: "talos_compilation",
            event_kind = "advisory_db_metadata_unreadable",
            copy = sample.copy.as_str(),
            path = crate::container::ADVISORY_DB_PATH,
            error = %e,
            "Could not date the baked RustSec advisory database — cargo audit --no-fetch \
             fails until the image is rebuilt with one"
        ),
    }
    sample
}

/// The wall-clock span the sampler's `Duration` type wants.
#[must_use]
pub const fn advisory_db_sample_interval() -> Duration {
    Duration::from_secs(ADVISORY_DB_AGE_SAMPLE_INTERVAL_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::Mutex;

    /// `TALOS_ADVISORY_DB_MAX_AGE_DAYS` is process-global; the one test that
    /// sets it takes this lock so no sibling reads a value it did not set.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const DAY: u64 = 86_400;

    fn set_age(path: &Path, secs_ago: u64) {
        let t = SystemTime::now() - Duration::from_secs(secs_ago);
        std::fs::File::open(path)
            .and_then(|f| f.set_modified(t))
            .unwrap_or_else(|e| panic!("backdate {}: {e}", path.display()));
    }

    #[test]
    fn age_is_the_freshest_of_three_signals() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let p = root.to_str().unwrap();
        // Signal 1 alone: the directory, 100 days old.
        set_age(root, 100 * DAY + 3600);
        assert_eq!(advisory_db_age_days(p).unwrap(), 100);
        // Signal 2: a fresher git ref wins over the stale directory.
        std::fs::create_dir_all(root.join(".git/refs/heads")).unwrap();
        let main = root.join(".git/refs/heads/main");
        std::fs::write(&main, "abc\n").unwrap();
        set_age(&main, 40 * DAY + 3600);
        set_age(root, 100 * DAY + 3600); // writing the ref refreshed the dir
        set_age(&root.join(".git"), 100 * DAY + 3600);
        assert_eq!(advisory_db_age_days(p).unwrap(), 40);
        // Signal 3: a fresher per-crate directory wins over both.
        std::fs::create_dir_all(root.join("crates/serde")).unwrap();
        set_age(&root.join("crates/serde"), 10 * DAY + 3600);
        set_age(&root.join("crates"), 100 * DAY + 3600);
        set_age(root, 100 * DAY + 3600);
        assert_eq!(advisory_db_age_days(p).unwrap(), 10);
        // Control: a STALER signal changes nothing.
        std::fs::create_dir_all(root.join("crates/old")).unwrap();
        set_age(&root.join("crates/old"), 300 * DAY);
        set_age(&root.join("crates"), 100 * DAY + 3600);
        set_age(root, 100 * DAY + 3600);
        assert_eq!(advisory_db_age_days(p).unwrap(), 10);
    }

    #[test]
    fn a_missing_or_future_dated_database_is_not_fresh() {
        let missing = advisory_db_age_days("/does/not/exist/advisory-db");
        assert!(
            matches!(missing, Err(AdvisoryDbAgeError::Unreadable(_))),
            "{missing:?}"
        );
        assert_ne!(
            missing.as_ref().ok(),
            Some(&0),
            "a missing DB must not read as built today"
        );

        let tmp = tempfile::tempdir().unwrap();
        let future = SystemTime::now() + Duration::from_secs(DAY);
        std::fs::File::open(tmp.path())
            .and_then(|f| f.set_modified(future))
            .unwrap();
        let dated = advisory_db_age_days(tmp.path().to_str().unwrap());
        assert!(
            matches!(dated, Err(AdvisoryDbAgeError::FutureDated)),
            "{dated:?}"
        );
    }

    #[test]
    fn verdict_boundaries_are_the_gates_thresholds() {
        use AdvisoryDbVerdict::*;
        assert_eq!(advisory_db_verdict(0, 90), Fresh);
        assert_eq!(advisory_db_verdict(29, 90), Fresh);
        assert_eq!(advisory_db_verdict(30, 90), Aging);
        assert_eq!(advisory_db_verdict(89, 90), Aging);
        assert_eq!(advisory_db_verdict(90, 90), Expired);
        // A limit at or below the warn threshold: expired wins over aging.
        assert_eq!(advisory_db_verdict(30, 30), Expired);
        assert_eq!(advisory_db_verdict(25, 20), Expired);
        assert_eq!(advisory_db_verdict(19, 20), Fresh);
    }

    #[test]
    fn the_gate_refuses_only_an_expired_copy_in_production() {
        use AdvisoryDbGateOutcome::*;
        assert_eq!(advisory_db_gate_outcome(29, 90, true), Pass);
        assert_eq!(advisory_db_gate_outcome(30, 90, true), WarnAging);
        assert_eq!(advisory_db_gate_outcome(89, 90, true), WarnAging);
        assert_eq!(advisory_db_gate_outcome(90, 90, true), Refuse);
        assert_eq!(
            advisory_db_gate_outcome(90, 90, false),
            WarnExpiredUnenforced
        );
        assert_eq!(
            advisory_db_gate_outcome(400, 90, false),
            WarnExpiredUnenforced
        );
        // The operator override is honoured in both directions.
        assert_eq!(advisory_db_gate_outcome(400, 1000, true), WarnAging);
        assert_eq!(advisory_db_gate_outcome(20, 20, true), Refuse);
    }

    #[test]
    fn max_age_reads_a_positive_env_value_else_the_default() {
        let _g = ENV_LOCK.lock().unwrap();
        let cases: [(Option<&str>, u64); 6] = [
            (None, ADVISORY_DB_DEFAULT_MAX_AGE_DAYS),
            (Some("100000"), 100_000),
            (Some(" 45 "), 45),
            (Some("0"), ADVISORY_DB_DEFAULT_MAX_AGE_DAYS),
            (Some("-3"), ADVISORY_DB_DEFAULT_MAX_AGE_DAYS),
            (Some("ninety"), ADVISORY_DB_DEFAULT_MAX_AGE_DAYS),
        ];
        for (value, expected) in cases {
            match value {
                Some(v) => std::env::set_var("TALOS_ADVISORY_DB_MAX_AGE_DAYS", v),
                None => std::env::remove_var("TALOS_ADVISORY_DB_MAX_AGE_DAYS"),
            }
            assert_eq!(advisory_db_max_age_days(), expected, "value {value:?}");
        }
        std::env::remove_var("TALOS_ADVISORY_DB_MAX_AGE_DAYS");
    }

    #[test]
    fn publish_sets_the_age_only_on_a_measured_sample() {
        let m = TalosMetrics::new().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        set_age(tmp.path(), 75 * DAY + 3600);
        let measured = sample_advisory_db_with(tmp.path().to_str().unwrap(), 90, true);
        assert_eq!(*measured.age_days.as_ref().unwrap(), 75);
        publish_advisory_db_sample(&m, &measured);
        let r = m.render_prometheus().unwrap();
        assert!(
            r.contains(r#"talos_advisory_db_age_days{copy="controller"} 75"#),
            "{r}"
        );
        assert!(r.contains(r#"talos_advisory_db_max_age_days{copy="controller"} 90"#));
        assert!(r.contains(r#"talos_advisory_db_age_enforced{copy="controller"} 1"#));
        assert!(r.contains(
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="measured"} 1"#
        ));
        assert!(r.contains(
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="unreadable"} 0"#
        ));

        // An unreadable sample: limits move, the age does NOT, the counter says so.
        let unreadable = sample_advisory_db_with("/does/not/exist/advisory-db", 120, false);
        assert!(unreadable.age_days.is_err());
        publish_advisory_db_sample(&m, &unreadable);
        let r = m.render_prometheus().unwrap();
        assert!(
            r.contains(r#"talos_advisory_db_age_days{copy="controller"} 75"#),
            "{r}"
        );
        assert!(r.contains(r#"talos_advisory_db_max_age_days{copy="controller"} 120"#));
        assert!(r.contains(r#"talos_advisory_db_age_enforced{copy="controller"} 0"#));
        assert!(r.contains(
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="measured"} 1"#
        ));
        assert!(r.contains(
            r#"talos_advisory_db_age_samples_total{copy="controller",outcome="unreadable"} 1"#
        ));
    }

    #[test]
    fn a_tick_without_a_registry_still_samples() {
        // No global registry in this binary: the tick must neither panic nor
        // publish; it returns what it read of the real baked path (absent on a
        // developer machine, present in the image).
        let s = sample_and_publish_advisory_db_age(None);
        assert_eq!(s.copy, AdvisoryDbCopy::Controller);
        assert!(s.max_age_days > 0);
    }

    /// The chart's thresholds are the gate's, read out of the rule file at
    /// compile time (package S's coupling rule): the aging alert fires at the
    /// gate's own warn constant, the expiry alert compares the age to the
    /// EXPORTED limit under the enforced reading rather than to a copied
    /// default, and the unreadable window outlasts two samples (an hourly
    /// sampler is up to one interval stale; one interval is a blip) but not
    /// eight.
    #[test]
    fn alerts_read_the_gates_own_thresholds() {
        const ALERTS: &str = include_str!("../../deploy/helm/talos/files/alerts.yaml");
        fn expr_of(alert: &str) -> String {
            let start = ALERTS
                .find(&format!("- alert: {alert}"))
                .unwrap_or_else(|| panic!("{alert} is not defined in alerts.yaml"));
            let block = &ALERTS[start..];
            let expr = block.find("expr:").expect("expr");
            let end = block[expr..].find("\n        for:").expect("for:");
            block[expr..expr + end].split_whitespace().collect()
        }
        let aging = expr_of("TalosAdvisoryDbAging");
        let after = aging
            .split("talos_advisory_db_age_days>=")
            .nth(1)
            .expect("TalosAdvisoryDbAging compares the age with >=");
        let threshold: u64 = after
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|d| d.parse().ok())
            .expect("a plain integer threshold");
        assert_eq!(threshold, ADVISORY_DB_WARN_AGE_DAYS);

        let expired = expr_of("TalosAdvisoryDbExpired");
        assert!(
            expired.contains("talos_advisory_db_age_days>=talos_advisory_db_max_age_days"),
            "{expired}"
        );
        assert!(
            expired.contains("talos_advisory_db_age_enforced==1"),
            "{expired}"
        );
        assert!(
            !expired.contains(&ADVISORY_DB_DEFAULT_MAX_AGE_DAYS.to_string()),
            "the expiry alert must read the exported limit, not a copied default"
        );

        let unreadable = expr_of("TalosAdvisoryDbUnreadable");
        assert!(
            unreadable.contains(r#"outcome="unreadable""#),
            "{unreadable}"
        );
        let window_h: u64 = unreadable
            .split('[')
            .nth(1)
            .and_then(|w| w.split('h').next())
            .and_then(|d| d.parse().ok())
            .expect("a window in whole hours");
        let window = window_h * 3600;
        assert!(
            window >= 2 * ADVISORY_DB_AGE_SAMPLE_INTERVAL_SECS,
            "{window}s"
        );
        assert!(
            window <= 8 * ADVISORY_DB_AGE_SAMPLE_INTERVAL_SECS,
            "{window}s"
        );
    }
}

//! The node_exporter textfile metric for the off-host upload.
//!
//! # Why this is the highest-risk part of the change
//!
//! The upload MUST NOT fail the local dump — a dump taken while the network
//! is down is still worth having, so a failed push warns and moves on. That
//! is the right behaviour and it is also exactly what makes a PERSISTENT
//! failure invisible. **A silently-failing upload is worse than no upload,
//! because it manufactures confidence in the one thing you would reach for
//! after losing the disk.** So the failure has to leave a trace that an
//! alert can see, and the alert has to be able to fire.
//!
//! # The two rules this file exists to obey
//!
//! 1. **Closed, pre-seeded label sets.** Every `kind`×`outcome` pair and
//!    every [`FailureReason`] is emitted on every run, at 0 if untouched.
//!    A Prometheus counter that has never been written does not exist, and
//!    `increase(absent[6h]) > 0` matches nothing — the detector would be
//!    silenced by its own subject until the first failure had already
//!    happened. No label value is ever derived from provider text.
//! 2. **Counters carry forward.** A textfile counter is whatever the file
//!    says, so each run must read the previous file and add to it. Writing
//!    per-run values instead would make every counter reset to 0 on every
//!    run, and `increase()` over a counter that resets every day is noise.
//!
//! # What this file does NOT establish
//!
//! That the metric is being SCRAPED. The producer and the collector are
//! different problems; the collector is `docker-compose.yml`'s
//! `node-exporter` service plus the `node-exporter` job in
//! `observability/prometheus/prometheus.yml`, and whether the running
//! Prometheus actually reads them is `make observability-verify`.

use std::collections::{BTreeMap, BTreeSet};

use crate::classify::FailureReason;
use crate::key::ArtifactKind;

/// Metric names, as bare constants.
///
/// Not inlined into the `format!` strings, and that is deliberate:
/// structural lint check 65(c) proves every `talos_*` series named in an
/// alert is registered somewhere, and its evidence is a bare double-quoted
/// literal in a `.rs` file. Interpolating the name into a wider format
/// string (`"talos_x{{kind=\"…\"}} {}"`) hides it from that check and the
/// alert would then read as alerting on a series nothing produces.
pub const M_UPLOADS: &str = "talos_offhost_backup_uploads_total";
pub const M_FAILURES: &str = "talos_offhost_backup_failures_total";
pub const M_LAST_SUCCESS: &str = "talos_offhost_backup_last_success_timestamp_seconds";
pub const M_LAST_RUN: &str = "talos_offhost_backup_last_run_timestamp_seconds";
pub const M_ENABLED: &str = "talos_offhost_backup_enabled";

/// The filename inside the textfile-collector directory. `node_exporter`
/// only reads `*.prom`.
pub const TEXTFILE_NAME: &str = "talos_offhost_backup.prom";

/// Per-run outcome. Closed set, two values — the third state people reach
/// for ("skipped, nothing to do") is deliberately NOT an outcome: a run
/// with nothing to upload has not failed and has not uploaded, and counting
/// it as either would make the counters lie about how much data is off-host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Success,
    Failure,
}

impl Outcome {
    pub const ALL: [Outcome; 2] = [Outcome::Success, Outcome::Failure];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
        }
    }
}

/// Everything the `.prom` file holds. Cumulative fields are carried forward
/// from the previous file; `last_run`/`enabled` describe this run only.
///
/// # The two counters count DIFFERENT THINGS, on purpose
///
/// * [`MetricState::uploads`] `{kind,outcome="failure"}` counts ARTIFACTS.
///   Three archives failing in one run is three, because that is what an
///   operator asking "how much did not get off this host" wants.
/// * [`MetricState::failures`] `{reason}` counts RUNS — **at most one per
///   reason per run**, enforced by `run_reasons` below.
///
/// The second is not a stylistic choice. `TalosOffhostBackupUploadFailing`
/// alerts on `increase(failures_total[50h]) > 1.5` and its description says
/// "has failed on at least two of the last two daily runs". Before this,
/// `do_upload` called `record_failure` once per artifact AND returned an
/// error on which `cmd_upload` called `record_run_failure` — so one bad
/// night on the encrypt/head/put paths scored 2–3 and the alert fired on a
/// single flaky tether, which is exactly the tightening from `> 0`/6 h to
/// `> 1.5`/50 h being defeated. The `.prom` fixture in the promtool suite
/// could not see it, because that fixture supplies counter values directly
/// instead of driving this producer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetricState {
    /// `1` when a bucket and an endpoint are configured. The staleness alert
    /// is gated on this so an operator who has not wired Tier 2 up yet does
    /// not get a permanently-red alert — a permanently-firing alert trains
    /// people to ignore red, which is the same defect one level up.
    pub enabled: bool,
    pub last_run: i64,
    pub uploads: BTreeMap<(ArtifactKind, Outcome), u64>,
    pub failures: BTreeMap<FailureReason, u64>,
    pub last_success: BTreeMap<ArtifactKind, i64>,
    /// Reasons already counted into `failures` during THIS run. Never
    /// rendered, never carried forward — a fresh run starts with an empty
    /// set, which is what makes `failures` a per-run counter.
    run_reasons: BTreeSet<FailureReason>,
}

impl MetricState {
    /// Start from the previous file's cumulative values. `None`/unparseable
    /// means "first ever run": every counter starts at 0, which is a real
    /// datapoint, not a gap.
    #[must_use]
    pub fn carried_forward(previous: Option<&str>) -> MetricState {
        let mut st = MetricState::default();
        let Some(text) = previous else {
            return st;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((lhs, rhs)) = line.rsplit_once(' ') else {
                continue;
            };
            let (name, labels) = split_labels(lhs);
            match name {
                M_UPLOADS => {
                    if let (Some(k), Some(o), Ok(v)) = (
                        label(labels, "kind").and_then(ArtifactKind::parse),
                        label(labels, "outcome").and_then(parse_outcome),
                        rhs.parse::<u64>(),
                    ) {
                        st.uploads.insert((k, o), v);
                    }
                }
                M_FAILURES => {
                    if let (Some(r), Ok(v)) = (
                        label(labels, "reason").and_then(FailureReason::parse),
                        rhs.parse::<u64>(),
                    ) {
                        st.failures.insert(r, v);
                    }
                }
                M_LAST_SUCCESS => {
                    if let (Some(k), Ok(v)) = (
                        label(labels, "kind").and_then(ArtifactKind::parse),
                        rhs.parse::<f64>(),
                    ) {
                        st.last_success.insert(k, v as i64);
                    }
                }
                _ => {}
            }
        }
        st
    }

    pub fn record_success(&mut self, kind: ArtifactKind, at_unix: i64) {
        *self.uploads.entry((kind, Outcome::Success)).or_insert(0) += 1;
        let e = self.last_success.entry(kind).or_insert(0);
        // Monotonic: an out-of-order run must not walk the timestamp
        // backwards and make a healthy pipeline look stale.
        if at_unix > *e {
            *e = at_unix;
        }
    }

    /// One ARTIFACT failed. Bumps the per-artifact counter unconditionally
    /// and the per-run reason counter at most once — see the type docs.
    pub fn record_failure(&mut self, kind: ArtifactKind, reason: FailureReason) {
        *self.uploads.entry((kind, Outcome::Failure)).or_insert(0) += 1;
        self.count_reason_once(reason);
    }

    /// A failure with no artifact in hand (bad config, missing `aws`,
    /// unreachable bucket at the listing step). It still has to be counted,
    /// or "the uploader cannot even start" is the one failure mode that
    /// produces no signal at all.
    ///
    /// Idempotent per reason within a run, so the normal path — `do_upload`
    /// records the per-artifact failure and then RETURNS that same failure,
    /// which `cmd_upload` records again as the run's outcome — counts one,
    /// not two. Both call sites are correct on their own terms; the
    /// de-duplication belongs here, where the invariant is stated and
    /// testable, rather than in a caller remembering not to.
    pub fn record_run_failure(&mut self, reason: FailureReason) {
        self.count_reason_once(reason);
    }

    fn count_reason_once(&mut self, reason: FailureReason) {
        if self.run_reasons.insert(reason) {
            *self.failures.entry(reason).or_insert(0) += 1;
        }
    }
}

fn parse_outcome(s: &str) -> Option<Outcome> {
    Outcome::ALL.into_iter().find(|o| o.as_str() == s)
}

fn split_labels(lhs: &str) -> (&str, &str) {
    match lhs.split_once('{') {
        Some((name, rest)) => (name, rest.strip_suffix('}').unwrap_or(rest)),
        None => (lhs, ""),
    }
}

fn label<'a>(labels: &'a str, want: &str) -> Option<&'a str> {
    labels.split(',').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == want).then(|| v.trim().trim_matches('"'))
    })
}

/// Render the whole `.prom` file.
///
/// Every series in the closed sets is emitted on every call, including the
/// ones that are 0. That is the pre-seeding rule: a label combination that
/// no call site can ever write must NOT be seeded (it would imply a wired
/// signal that does not exist), and every combination that a call site CAN
/// write must be, so the alert on it is well-defined before it first fires.
#[must_use]
pub fn render(st: &MetricState) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "# HELP {M_ENABLED} 1 when an off-host backup destination is configured on this host.\n\
         # TYPE {M_ENABLED} gauge\n\
         {M_ENABLED} {}\n",
        u8::from(st.enabled)
    ));

    out.push_str(&format!(
        "# HELP {M_LAST_RUN} Unix timestamp of the most recent off-host upload attempt.\n\
         # TYPE {M_LAST_RUN} gauge\n\
         {M_LAST_RUN} {}\n",
        st.last_run
    ));

    out.push_str(&format!(
        "# HELP {M_UPLOADS} Off-host archive uploads, by artifact kind and outcome.\n\
         # TYPE {M_UPLOADS} counter\n"
    ));
    for kind in ArtifactKind::ALL {
        for outcome in Outcome::ALL {
            let v = st.uploads.get(&(kind, outcome)).copied().unwrap_or(0);
            out.push_str(&format!(
                "{M_UPLOADS}{{kind=\"{}\",outcome=\"{}\"}} {v}\n",
                kind.as_str(),
                outcome.as_str()
            ));
        }
    }

    out.push_str(&format!(
        "# HELP {M_FAILURES} Off-host upload failures, by classified reason.\n\
         # TYPE {M_FAILURES} counter\n"
    ));
    for reason in FailureReason::ALL {
        let v = st.failures.get(&reason).copied().unwrap_or(0);
        out.push_str(&format!(
            "{M_FAILURES}{{reason=\"{}\"}} {v}\n",
            reason.as_str()
        ));
    }

    out.push_str(&format!(
        "# HELP {M_LAST_SUCCESS} Unix timestamp of the most recent SUCCESSFUL off-host upload, per kind.\n\
         # TYPE {M_LAST_SUCCESS} gauge\n"
    ));
    for kind in ArtifactKind::ALL {
        // 0, never absent. `time() - 0` is a very large number, so the
        // staleness alert fires for a host that has never uploaded — which
        // is precisely the case it exists to catch. Omitting the series
        // instead would make that case match nothing.
        let v = st.last_success.get(&kind).copied().unwrap_or(0);
        out.push_str(&format!(
            "{M_LAST_SUCCESS}{{kind=\"{}\"}} {v}\n",
            kind.as_str()
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_closed_label_combination_is_pre_seeded() {
        // The whole D2 requirement in one assertion: before anything has
        // ever been uploaded, every series an alert can reference already
        // exists at 0. Without this, `increase(...) > 0` is evaluated over
        // an absent series and matches nothing.
        let text = render(&MetricState::default());
        for kind in ArtifactKind::ALL {
            for outcome in Outcome::ALL {
                let want = format!(
                    "{M_UPLOADS}{{kind=\"{}\",outcome=\"{}\"}} 0",
                    kind.as_str(),
                    outcome.as_str()
                );
                assert!(text.contains(&want), "missing pre-seed: {want}");
            }
            assert!(text.contains(&format!("{M_LAST_SUCCESS}{{kind=\"{}\"}} 0", kind.as_str())));
        }
        for reason in FailureReason::ALL {
            let want = format!("{M_FAILURES}{{reason=\"{}\"}} 0", reason.as_str());
            assert!(text.contains(&want), "missing pre-seed: {want}");
        }
        assert!(text.contains(&format!("{M_ENABLED} 0")));
    }

    #[test]
    fn seeded_series_count_is_exactly_the_closed_sets() {
        // Seeding a combination NOTHING can write implies a wired signal
        // that does not exist. Pin the count so a future label addition is
        // a deliberate act.
        let text = render(&MetricState::default());
        let samples = text
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .count();
        // 1 enabled + 1 last_run + (2 kinds × 2 outcomes) + 7 reasons + 2 last_success
        assert_eq!(samples, 1 + 1 + 4 + 7 + 2);
    }

    #[test]
    fn counters_carry_forward_across_runs() {
        // A textfile counter that resets every run is not a counter.
        let mut first = MetricState::default();
        first.record_success(ArtifactKind::Postgres, 1000);
        first.record_failure(ArtifactKind::Vault, FailureReason::Network);
        let text = render(&first);

        let mut second = MetricState::carried_forward(Some(&text));
        second.record_success(ArtifactKind::Postgres, 2000);
        assert_eq!(
            second
                .uploads
                .get(&(ArtifactKind::Postgres, Outcome::Success)),
            Some(&2)
        );
        assert_eq!(
            second.uploads.get(&(ArtifactKind::Vault, Outcome::Failure)),
            Some(&1)
        );
        assert_eq!(second.failures.get(&FailureReason::Network), Some(&1));
        assert_eq!(
            second.last_success.get(&ArtifactKind::Postgres),
            Some(&2000)
        );
    }

    #[test]
    fn render_parse_round_trips_exactly() {
        let mut st = MetricState {
            enabled: true,
            last_run: 12_345,
            ..MetricState::default()
        };
        st.record_success(ArtifactKind::Postgres, 111);
        st.record_success(ArtifactKind::Vault, 222);
        st.record_failure(ArtifactKind::Postgres, FailureReason::Auth);
        st.record_run_failure(FailureReason::Config);

        let back = MetricState::carried_forward(Some(&render(&st)));
        // Every value survives. `back` additionally carries the PRE-SEEDED
        // zeros for combinations this run never touched — that is the point
        // of the seeding, not a round-trip defect, so the assertion is
        // "everything written comes back, and everything extra is 0".
        for (k, v) in &st.uploads {
            assert_eq!(back.uploads.get(k), Some(v), "lost {k:?}");
        }
        for (k, v) in &back.uploads {
            if !st.uploads.contains_key(k) {
                assert_eq!(*v, 0, "invented a non-zero counter for {k:?}");
            }
        }
        for (k, v) in &st.failures {
            assert_eq!(back.failures.get(k), Some(v), "lost {k:?}");
        }
        for (k, v) in &back.failures {
            if !st.failures.contains_key(k) {
                assert_eq!(*v, 0, "invented a non-zero counter for {k:?}");
            }
        }
        for (k, v) in &st.last_success {
            assert_eq!(back.last_success.get(k), Some(v), "lost {k:?}");
        }
        // `enabled`/`last_run` describe THIS run and are deliberately not
        // carried forward — a run that did not happen must not inherit a
        // timestamp claiming it did.
        assert!(!back.enabled);
        assert_eq!(back.last_run, 0);
    }

    #[test]
    fn one_failed_run_counts_exactly_one_per_reason() {
        // The alert reads `increase(failures_total[50h]) > 1.5` and claims
        // that means "failed on at least two of the last two daily runs".
        // That claim is only true if ONE run can only ever add 1.
        let mut run = MetricState::default();
        // Three artifacts fail the same way, then the run itself fails with
        // that reason — the real do_upload/cmd_upload sequence.
        run.record_failure(ArtifactKind::Postgres, FailureReason::Network);
        run.record_failure(ArtifactKind::Vault, FailureReason::Network);
        run.record_failure(ArtifactKind::Postgres, FailureReason::Network);
        run.record_run_failure(FailureReason::Network);
        assert_eq!(
            run.failures.get(&FailureReason::Network),
            Some(&1),
            "one run must move failures_total{{reason}} by exactly 1"
        );
        // The per-ARTIFACT counter is unaffected: it is a different question
        // ("how much did not get off this host") and 3 is the right answer.
        assert_eq!(
            run.uploads.get(&(ArtifactKind::Postgres, Outcome::Failure)),
            Some(&2)
        );
        assert_eq!(
            run.uploads.get(&(ArtifactKind::Vault, Outcome::Failure)),
            Some(&1)
        );

        // Distinct reasons in one run are still distinct — the dedupe is per
        // reason, not per run, so `sum by (reason)` stays meaningful.
        run.record_failure(ArtifactKind::Vault, FailureReason::Encrypt);
        assert_eq!(run.failures.get(&FailureReason::Encrypt), Some(&1));

        // And the NEXT run counts again: the dedupe must not be baked into
        // the carried-forward file, or a persistent failure would be
        // counted once and then never again — silence, which is the defect
        // one level worse.
        let mut next = MetricState::carried_forward(Some(&render(&run)));
        next.record_run_failure(FailureReason::Network);
        assert_eq!(next.failures.get(&FailureReason::Network), Some(&2));
    }

    #[test]
    fn last_success_never_walks_backwards() {
        let mut st = MetricState::default();
        st.record_success(ArtifactKind::Postgres, 5000);
        st.record_success(ArtifactKind::Postgres, 4000);
        assert_eq!(
            st.last_success.get(&ArtifactKind::Postgres),
            Some(&5000),
            "an out-of-order run must not make a healthy pipeline look stale"
        );
    }

    #[test]
    fn a_corrupt_previous_file_degrades_to_zero_not_to_a_panic() {
        // The file lives in a directory anyone on this host can write. A
        // half-written or hand-edited file must not take the uploader down —
        // it must reset to 0, which reads as "counters restarted" rather
        // than as silence.
        for junk in [
            "",
            "garbage",
            "talos_offhost_backup_uploads_total",
            "talos_offhost_backup_uploads_total{kind=\"nope\",outcome=\"success\"} 4",
            "talos_offhost_backup_failures_total{reason=\"auth\"} not-a-number",
            "# HELP only a comment",
        ] {
            let st = MetricState::carried_forward(Some(junk));
            assert!(st.uploads.is_empty() || st.uploads.values().all(|v| *v > 0));
            let _ = render(&st); // must not panic
        }
    }

    #[test]
    fn unknown_label_values_are_dropped_not_admitted() {
        // A hand-edited file must not be able to inject an unbounded label
        // value into the next render.
        let st = MetricState::carried_forward(Some(
            "talos_offhost_backup_failures_total{reason=\"$(whoami)\"} 9\n",
        ));
        assert!(st.failures.is_empty());
        let text = render(&st);
        assert!(!text.contains("whoami"));
    }

    #[test]
    fn output_is_valid_prometheus_text_format() {
        let mut st = MetricState {
            enabled: true,
            last_run: 99,
            ..MetricState::default()
        };
        st.record_failure(ArtifactKind::Vault, FailureReason::Encrypt);
        let text = render(&st);
        // Every family declares HELP and TYPE before its first sample, and
        // every sample line is `name[{labels}] value`. node_exporter drops
        // the WHOLE file on a parse error, taking the drill's own metric
        // with it if they ever shared a file — they do not, but a malformed
        // file would still show up only as node_textfile_scrape_error.
        let mut seen_help = 0;
        let mut seen_type = 0;
        for line in text.lines() {
            if line.starts_with("# HELP ") {
                seen_help += 1;
            } else if line.starts_with("# TYPE ") {
                seen_type += 1;
            } else {
                let (_, v) = line.rsplit_once(' ').expect("sample has a value");
                assert!(v.parse::<f64>().is_ok(), "bad sample line: {line}");
            }
        }
        assert_eq!(seen_help, 5);
        assert_eq!(seen_type, 5);
    }

    #[test]
    fn metric_names_are_the_ones_the_alerts_use() {
        // Renaming a series orphans every alert and dashboard on the old
        // name while everything still compiles. Pinned deliberately.
        assert_eq!(M_UPLOADS, "talos_offhost_backup_uploads_total");
        assert_eq!(M_FAILURES, "talos_offhost_backup_failures_total");
        assert_eq!(
            M_LAST_SUCCESS,
            "talos_offhost_backup_last_success_timestamp_seconds"
        );
        assert_eq!(
            M_LAST_RUN,
            "talos_offhost_backup_last_run_timestamp_seconds"
        );
        assert_eq!(M_ENABLED, "talos_offhost_backup_enabled");
    }
}

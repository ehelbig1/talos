//! What to upload, and how old the bucket's newest copy is.
//!
//! Two pure questions, both of which must be answerable without a bucket:
//!
//! * **Which local artifacts are missing off-host?** — [`plan_uploads`]
//! * **Is the newest off-host copy fresh enough to certify anything?** —
//!   [`newest_for_kind`] + [`age_hours`]
//!
//! The second is the one that matters. The restore drill's artifact-age gate
//! (2026-08-13) exists because a value that is COMPUTED, DISPLAYED and never
//! COMPARED lets a dead sidecar go green for as long as its last good file
//! survives retention. The off-host copy has exactly the same failure mode
//! one hop further out, so it gets the same treatment: the drill asserts the
//! age of the object it pulled, and refuses a stale one.
//!
//! **An age gate has two ends.** [`age_hours`] saturates to 0 on a future
//! stamp, so a stale-only check re-creates the very defect it was written
//! against — one future-dated key reads as fresh FOREVER, and a replay of an
//! old-but-valid archive under such a key passes every downstream verifier.
//! [`is_implausibly_future`] is the other end, and both are asserted
//! together.

use crate::key::{object_key, parse_object_key, stamp_of_local, ArtifactKind, KeyError};

/// A backup artifact sitting in `$BACKUP_DIR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalArtifact {
    pub kind: ArtifactKind,
    /// Basename only. The absolute path is the caller's business; putting it
    /// in here invites it into an object key or a log line.
    pub filename: String,
    /// Derived from the filename, not from the file's mtime. An mtime is
    /// rewritten by `cp -p`-less copies, by restores and by backup tools; the
    /// stamp the sidecar wrote into the name is the artifact's real age.
    pub taken_at_unix: i64,
}

impl LocalArtifact {
    /// Build from a bare filename, rejecting anything that is not a
    /// well-formed artifact of `kind`.
    pub fn from_filename(kind: ArtifactKind, filename: &str) -> Result<LocalArtifact, KeyError> {
        // Go through object_key first so the character allowlist and the
        // shape check apply here too — a name that cannot become a key is
        // not an artifact, and letting it into a plan only defers the error.
        let _ = object_key(kind, filename)?;
        let stamp = stamp_of_local(kind, filename)?;
        Ok(LocalArtifact {
            kind,
            filename: filename.to_string(),
            taken_at_unix: stamp
                .to_unix()
                .ok_or_else(|| KeyError::NoStamp(filename.to_string()))?,
        })
    }

    /// This artifact's object key.
    pub fn object_key(&self) -> Result<String, KeyError> {
        object_key(self.kind, &self.filename)
    }
}

/// How much of the local history to push.
///
/// **This is the "next dump onward vs. one-time backfill" decision, made
/// explicitly rather than left to whatever the code happens to do.**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadMode {
    /// DEFAULT. Upload only the NEWEST local artifact of each kind, and only
    /// if the bucket does not already have it.
    ///
    /// Rationale: a `pg_dump` is cumulative, so the newest dump contains the
    /// entire history — every `ml_examples` row, every `actor_memory` row.
    /// One newest-of-each-kind archive per day is the whole recovery story;
    /// the older local dumps are point-in-time convenience, not additional
    /// data. Pushing only the newest also means enabling this does not
    /// silently start a multi-gigabyte first run on a laptop tether.
    ///
    /// Note this is "newest onward" **including today's** — the first run
    /// uploads immediately rather than waiting for the sidecar's next tick,
    /// so the drill has something to restore from within minutes.
    NewestOnly,
    /// One-time opt-in: upload every retained local artifact that the bucket
    /// does not have. Use once, deliberately, if point-in-time recovery to a
    /// day inside the retention window matters more than the egress.
    Backfill,
}

/// Decide what to send.
///
/// `remote_keys` is the bucket listing. An artifact whose key is already
/// present is SKIPPED, never re-PUT: `put-object` over an existing key
/// overwrites it, so "upload everything and let the bucket sort it out"
/// would destroy history with a credential that is not allowed to delete.
/// See [`crate::aws::head_object_argv`] for why this is a guard and not a
/// control.
///
/// Returns newest-first, so a partial run (interrupted, rate-limited) has
/// still sent the most valuable archive.
#[must_use]
pub fn plan_uploads(
    local: &[LocalArtifact],
    remote_keys: &[String],
    mode: UploadMode,
) -> Vec<LocalArtifact> {
    let mut chosen: Vec<LocalArtifact> = Vec::new();
    for kind in ArtifactKind::ALL {
        let mut of_kind: Vec<&LocalArtifact> = local.iter().filter(|a| a.kind == kind).collect();
        of_kind.sort_by(|a, b| {
            b.taken_at_unix
                .cmp(&a.taken_at_unix)
                .then_with(|| a.filename.cmp(&b.filename))
        });
        let candidates: Vec<&LocalArtifact> = match mode {
            UploadMode::NewestOnly => of_kind.into_iter().take(1).collect(),
            UploadMode::Backfill => of_kind,
        };
        for a in candidates {
            match a.object_key() {
                Ok(k) if !remote_keys.iter().any(|r| r == &k) => chosen.push(a.clone()),
                _ => {}
            }
        }
    }
    chosen.sort_by(|a, b| {
        b.taken_at_unix
            .cmp(&a.taken_at_unix)
            .then_with(|| a.kind.cmp(&b.kind))
    });
    chosen
}

/// The newest object of a kind in a listing, as `(key, taken_at_unix)`.
///
/// Ordering is by the stamp PARSED OUT OF THE KEY, never by the object's
/// `LastModified`: a re-upload, a bucket copy or a provider-side migration
/// rewrites `LastModified` and would then make an old dump look fresh. The
/// key is derived from the artifact and cannot be rewritten without becoming
/// a different key.
#[must_use]
pub fn newest_for_kind(remote_keys: &[String], kind: ArtifactKind) -> Option<(String, i64)> {
    remote_keys
        .iter()
        .filter_map(|k| {
            let (got_kind, stamp) = parse_object_key(k)?;
            if got_kind != kind {
                return None;
            }
            Some((k.clone(), stamp.to_unix()?))
        })
        .max_by_key(|(_, at)| *at)
}

/// How far into the future a key stamp may sit before it is REFUSED rather
/// than believed.
///
/// 24 h is chosen to be far wider than any clock error that survives on a
/// networked host (NTP keeps a laptop inside seconds; a dead RTC battery or a
/// wrong timezone offset lands inside a day) and far narrower than any useful
/// replay window. See [`is_implausibly_future`] for why a bound is needed at
/// all.
pub const MAX_FUTURE_SKEW_HOURS: i64 = 24;

/// Whole hours between `taken_at_unix` and `now_unix`.
///
/// Saturates at 0 for a future timestamp rather than returning a negative
/// number, so callers never have to reason about a negative age.
///
/// **That saturation is why [`is_implausibly_future`] exists and why every
/// freshness gate MUST call it.** A future stamp reads as 0 h old — i.e. as
/// permanently fresh — so on its own this function cannot fail a
/// future-dated object, ever.
#[must_use]
pub fn age_hours(taken_at_unix: i64, now_unix: i64) -> i64 {
    (now_unix.saturating_sub(taken_at_unix) / 3600).max(0)
}

/// Is this stamp further in the future than any real clock error?
///
/// **This closes a REPLAY, not merely a poisoning.** The uploader's
/// credential holds `readFiles` as well as `writeFiles` — the restore drill
/// needs it — so anyone holding it can `GET` the current newest archive and
/// `PUT` those exact bytes back under a future-dated key. That object is a
/// genuine, correctly-encrypted archive: it decrypts, `pg_restore
/// --exit-on-error` succeeds, and every verifier the drill runs passes. The
/// drill would report SUCCESS while restoring a replay of an arbitrarily old
/// database. And because [`newest_for_kind`] picks the highest stamp while
/// [`age_hours`] saturates to 0, that one object shadows every real archive
/// AND reads as 0 h old forever — disabling the freshness gate permanently
/// rather than for a day.
///
/// No attacker is needed for the same outcome: the stamp comes from the
/// sidecar's filename, so a single upload from a host with a skewed clock
/// does it by accident.
///
/// The choice is NOT "reject future keys or accept false-reds on skew" — a
/// BOUNDED tolerance closes it with neither cost. A stamp inside
/// [`MAX_FUTURE_SKEW_HOURS`] is accepted and (per [`age_hours`]) reads as
/// 0 h old; beyond it the object is refused and the caller says so.
#[must_use]
pub fn is_implausibly_future(taken_at_unix: i64, now_unix: i64) -> bool {
    taken_at_unix.saturating_sub(now_unix) > MAX_FUTURE_SKEW_HOURS * 3600
}

/// Whole hours a stamp sits in the FUTURE, 0 if it does not. For messages
/// only — the decision is [`is_implausibly_future`].
#[must_use]
pub fn future_skew_hours(taken_at_unix: i64, now_unix: i64) -> i64 {
    (taken_at_unix.saturating_sub(now_unix) / 3600).max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pg(name: &str) -> LocalArtifact {
        LocalArtifact::from_filename(ArtifactKind::Postgres, name).unwrap()
    }
    fn vault(name: &str) -> LocalArtifact {
        LocalArtifact::from_filename(ArtifactKind::Vault, name).unwrap()
    }

    #[test]
    fn newest_only_picks_one_of_each_kind() {
        let local = vec![
            pg("talos-20260815-000000.dump"),
            pg("talos-20260817-101757.dump"),
            pg("talos-20260816-000000.dump"),
            vault("vault-20260814-221124.tar.gz"),
            vault("vault-20260817-221124.tar.gz"),
        ];
        let plan = plan_uploads(&local, &[], UploadMode::NewestOnly);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].filename, "vault-20260817-221124.tar.gz");
        assert_eq!(plan[1].filename, "talos-20260817-101757.dump");
    }

    #[test]
    fn backfill_takes_everything_missing() {
        let local = vec![
            pg("talos-20260815-000000.dump"),
            pg("talos-20260817-101757.dump"),
            vault("vault-20260817-221124.tar.gz"),
        ];
        let plan = plan_uploads(&local, &[], UploadMode::Backfill);
        assert_eq!(plan.len(), 3);
        // Newest first: an interrupted run has still sent the best archive.
        assert!(plan[0].taken_at_unix >= plan[1].taken_at_unix);
        assert!(plan[1].taken_at_unix >= plan[2].taken_at_unix);
    }

    #[test]
    fn an_artifact_already_in_the_bucket_is_never_re_put() {
        // Re-PUTting an existing key OVERWRITES it. With a no-delete
        // credential that is the ONLY way this code could destroy history,
        // so it is the property most worth pinning.
        let a = pg("talos-20260817-101757.dump");
        let remote = vec![a.object_key().unwrap()];
        assert!(plan_uploads(&[a.clone()], &remote, UploadMode::NewestOnly).is_empty());
        assert!(plan_uploads(&[a], &remote, UploadMode::Backfill).is_empty());
    }

    #[test]
    fn newest_only_does_not_fall_back_to_an_older_dump() {
        // If the newest is already uploaded, the run has nothing to do —
        // it must NOT quietly start pushing yesterday's instead, which
        // would look like healthy activity while today's went missing.
        let newest = pg("talos-20260817-101757.dump");
        let older = pg("talos-20260816-000000.dump");
        let remote = vec![newest.object_key().unwrap()];
        let plan = plan_uploads(&[newest, older], &remote, UploadMode::NewestOnly);
        assert!(plan.is_empty());
    }

    #[test]
    fn an_unrelated_bucket_prefix_does_not_satisfy_an_artifact() {
        let a = pg("talos-20260817-101757.dump");
        let remote = vec![
            "talos/v1/postgres/2026/08/20260816T000000Z-postgres.age".to_string(),
            "some/other/thing.age".to_string(),
        ];
        assert_eq!(plan_uploads(&[a], &remote, UploadMode::NewestOnly).len(), 1);
    }

    #[test]
    fn newest_for_kind_orders_by_the_key_stamp_not_by_listing_order() {
        let keys = vec![
            "talos/v1/postgres/2026/08/20260817T101757Z-postgres.age".to_string(),
            "talos/v1/postgres/2026/08/20260810T101757Z-postgres.age".to_string(),
            "talos/v1/vault/2026/08/20260818T221124Z-vault.age".to_string(),
            "talos/v1/postgres/2026/08/20260812T101757Z-postgres.age".to_string(),
        ];
        let (k, at) = newest_for_kind(&keys, ArtifactKind::Postgres).unwrap();
        assert_eq!(k, "talos/v1/postgres/2026/08/20260817T101757Z-postgres.age");
        assert_eq!(at, 1_786_961_877); // 2026-08-17T10:17:57Z
        let (vk, _) = newest_for_kind(&keys, ArtifactKind::Vault).unwrap();
        assert!(vk.contains("vault"));
    }

    #[test]
    fn newest_for_kind_is_none_on_an_empty_or_foreign_bucket() {
        assert!(newest_for_kind(&[], ArtifactKind::Postgres).is_none());
        // A bucket with only unrelated objects must read as EMPTY, not as
        // "something is there". The drill turns None into a failure.
        let junk = vec!["backup.tar".to_string(), "talos/v1/".to_string()];
        assert!(newest_for_kind(&junk, ArtifactKind::Postgres).is_none());
    }

    #[test]
    fn age_hours_never_goes_negative() {
        assert_eq!(age_hours(1000, 1000 + 3600 * 5), 5);
        assert_eq!(age_hours(1000, 1000 + 3599), 0);
        // A future stamp still saturates at 0 — i.e. reads as FRESH. That is
        // now a documented property of THIS function only, and it is exactly
        // why no caller may use it as its whole freshness gate: the future
        // end is `is_implausibly_future`, asserted below.
        assert_eq!(age_hours(9_999_999, 1000), 0);
    }

    #[test]
    fn a_replayable_future_stamp_is_refused_but_ordinary_clock_skew_is_not() {
        // THE property. A future-dated key is not merely "junk that fails
        // loudly": with `readFiles` on the same credential, an attacker (or
        // one host with a skewed clock) can re-PUT the CURRENT newest archive
        // under a future key. It decrypts, it restores, every verifier
        // passes — and because `age_hours` saturates, that key reads 0h old
        // forever, disabling the freshness gate permanently.
        let now = 1_786_961_877;
        let h = 3600;

        // Ordinary skew is accepted, so this is not a false-red machine.
        assert!(!is_implausibly_future(now, now));
        assert!(!is_implausibly_future(now + h, now));
        assert!(!is_implausibly_future(now + 23 * h, now));
        // Exactly at the bound is still accepted; strictly beyond is not.
        assert!(!is_implausibly_future(now + MAX_FUTURE_SKEW_HOURS * h, now));
        assert!(is_implausibly_future(
            now + MAX_FUTURE_SKEW_HOURS * h + 1,
            now
        ));
        assert!(is_implausibly_future(now + 48 * h, now));
        assert!(is_implausibly_future(now + 365 * 24 * h, now));

        // A past stamp is never "future", however old — staleness is the
        // other gate's job.
        assert!(!is_implausibly_future(now - 365 * 24 * h, now));

        // No overflow panic on the extremes a hand-made key could carry.
        assert!(is_implausibly_future(i64::MAX, now));
        assert!(!is_implausibly_future(i64::MIN, now));
        assert_eq!(age_hours(i64::MIN, i64::MAX), i64::MAX / 3600);

        // The reporting helper, used only in the refusal message.
        assert_eq!(future_skew_hours(now + 50 * h, now), 50);
        assert_eq!(future_skew_hours(now - 50 * h, now), 0);
    }

    #[test]
    fn malformed_local_names_never_enter_a_plan() {
        for bad in [
            "talos-20260817-101757.dump.partial",
            "talos-nope.dump",
            "../talos-20260817-101757.dump",
        ] {
            assert!(LocalArtifact::from_filename(ArtifactKind::Postgres, bad).is_err());
        }
    }
}

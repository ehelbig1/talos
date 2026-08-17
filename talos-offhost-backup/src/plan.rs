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

/// Whole hours between `taken_at_unix` and `now_unix`.
///
/// Saturates at 0 for a future timestamp rather than returning a negative
/// number, so callers never have to reason about a negative age.
///
/// STATED CONSEQUENCE, in the permissive direction: **a future-dated key
/// therefore reads as fresh.** Combined with [`newest_for_kind`] picking the
/// highest key stamp, anyone holding the write credential can upload a
/// far-future object and have it shadow the real newest archive
/// indefinitely. That is a denial/poisoning vector, not a data-loss one —
/// the real archives are untouched under their own keys, and the drill fails
/// LOUDLY on the poisoned object (its decrypt or its `pg_restore` will not
/// succeed) rather than going green. It is the same residual as "an attacker
/// with the credential can upload garbage", which `docs/offhost-backup.md`
/// states, and it is not closed here.
#[must_use]
pub fn age_hours(taken_at_unix: i64, now_unix: i64) -> i64 {
    ((now_unix - taken_at_unix) / 3600).max(0)
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
        // A future stamp saturates at 0 rather than going negative — which
        // means it reads as FRESH. Pinned here so the permissive direction is
        // a decision on record, not an accident; see the doc comment for why
        // it is left open and what catches the poisoned-object case instead.
        assert_eq!(age_hours(9_999_999, 1000), 0);
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

//! Object-key construction.
//!
//! **A bucket listing is metadata, and metadata leaks.** Whoever can list the
//! bucket learns every key name, so a key may carry only what is already
//! implied by the bucket existing: which artifact family this is and when it
//! was taken. No user id, no actor id, no hostname, no vault path, no
//! database name, no local filesystem path.
//!
//! Keys are DERIVED, not generated: the same local artifact always maps to
//! the same key. That is what makes "upload what is missing" idempotent —
//! a re-run cannot produce a second copy under a fresh name, and the
//! pre-flight existence check has something stable to check.
//!
//! Uniqueness across time comes from the timestamp the backup sidecar
//! already puts in the filename. Two artifacts of the same kind cannot share
//! a second unless they are the same dump.

use std::fmt;

/// Which backup family an artifact belongs to.
///
/// # `neo4j` used to be absent on purpose. Its own stated trigger fired.
///
/// The comment here read: *"the graph is reconstructible from `actor_memory`
/// via `graph_backfill`, so paying egress and a second fatal secret's blast
/// radius for it is not worth it — if the graph ever stops being
/// reconstructible, add it here."* It is REPLACED rather than deleted, because
/// the reasoning was sound when written and decayed afterwards, and that shape
/// is the thing worth remembering.
///
/// **Measured 2026-08-26 against both live stores.** Neo4j held 1,283 nodes /
/// 1,939 relationships under 13 distinct `source_key`s spanning 16 distinct
/// (`actor_id`, `source_key`) pairs; `actor_memory` held 18 rows / 15 keys.
/// **6 of those 16 pairs — 191 nodes, 14.9 % — had no surviving row to rebuild
/// from.** 90 of the 191 never had one: `reflection_synthesis` is a sentinel
/// stamped by the reflection loop (`talos_graph_rag`'s `SYNTHESIS_SOURCE_KEY`),
/// not an `actor_memory` key, and `graph_backfill` iterates `actor_memory`
/// rows — so no retention policy and no re-run can re-emit it.
///
/// The survivors are weaker than a key-level count suggests. Graph nodes
/// ACCUMULATE over every value a mutable `latest` key has ever held
/// (`daily_brief/latest`: 323 nodes spanning 40 days) while `actor_memory`
/// keeps only the current one, and extraction falls back to an LLM — so a
/// re-run is a fresh generation, not a replay.
///
/// A graph is rebuildable; *that* graph is not recoverable. The second fatal
/// secret never materialised either: this artifact rides the SAME `age`
/// passphrase as the other two.
///
/// **This claim is a dated measurement, exactly like the one it replaces.**
/// Re-derive it before relying on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactKind {
    /// `pg_dump --format=custom` of the whole database.
    Postgres,
    /// Opaque tar of Vault's file backend (`/vault/file`).
    Vault,
    /// Opaque tar of Neo4j's data directory (`/neo4j-data` — `databases/`,
    /// `transactions/`, `dbms/auth.ini`). A raw store-file copy, NOT a
    /// `neo4j-admin database dump`, so a restore is "stop the server, replace
    /// the data directory, start" rather than a load command.
    ///
    /// **Appended, never inserted.** [`ArtifactKind::ALL`] order is the order
    /// the metric exposition is rendered in; putting a new kind in the middle
    /// would reorder existing lines for no benefit.
    ///
    /// Uploadable and fetchable as of 2026-08-26.
    ///
    /// **Restore-drilled as of 2026-08-26, for `--source artifact` only.**
    /// The sentence here previously read "NOT restored by
    /// `scripts/drills/backup-restore.sh`", which was true when written and
    /// is the reason the leg exists; it is replaced rather than deleted
    /// because the shape — an omission recorded honestly, then closed — is
    /// the thing worth remembering. The drill now extracts the archive into
    /// a scratch volume, starts a version-pinned Neo4j on it, waits for the
    /// database to reach `online` (transaction recovery), and compares the
    /// restored node/relationship counts against the `neo4j_nodes=` /
    /// `neo4j_relationships=` the sidecar wrote into the artifact's own
    /// manifest.
    ///
    /// **Still NOT restored by `--source b2`.** The off-host branch fetches
    /// postgres and vault only, so a green `--source b2` drill certifies 2 of
    /// these 3 kinds. It says so: the drill emits
    /// `talos_backup_drill_kind_verified{source,kind}` and writes no line for
    /// a kind it did not attempt. See `docs/offhost-backup.md` and
    /// `scripts/drills/README.md`.
    Neo4j,
}

impl ArtifactKind {
    /// Every kind, in a stable order. Closed set — the metric label values
    /// are pre-seeded from this, so `increase(...) > 0` is well-defined
    /// before the first upload ever happens.
    ///
    /// **Adding a variant does NOT break this array.** The length is a
    /// literal, so a 2-element `ALL` compiles cleanly against a 3-variant
    /// enum — and the three `for kind in ArtifactKind::ALL` loops
    /// (`discover_local`, `plan_uploads`, `metrics::render`) would then skip
    /// the new kind in silence: never discovered, never planned, never
    /// pre-seeded, with a green metric throughout. Nothing in the compiler
    /// catches that, which is why the unit test
    /// `all_is_pinned_and_exhaustive` pins the length and the label list by
    /// hand instead of deriving them from `ALL`. (Named, not linked — it is
    /// `#[cfg(test)]`, so an intra-doc link to it would not resolve.)
    pub const ALL: [ArtifactKind; 3] = [
        ArtifactKind::Postgres,
        ArtifactKind::Vault,
        ArtifactKind::Neo4j,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Postgres => "postgres",
            ArtifactKind::Vault => "vault",
            ArtifactKind::Neo4j => "neo4j",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "postgres" => Some(ArtifactKind::Postgres),
            "vault" => Some(ArtifactKind::Vault),
            "neo4j" => Some(ArtifactKind::Neo4j),
            _ => None,
        }
    }

    /// Sub-directory of `$BACKUP_DIR` the sidecar writes this kind into.
    /// Empty string means the root.
    #[must_use]
    pub fn backup_subdir(self) -> &'static str {
        match self {
            ArtifactKind::Postgres => "",
            ArtifactKind::Vault => "vault",
            ArtifactKind::Neo4j => "neo4j",
        }
    }

    /// Local filename prefix written by `scripts/dev-backup/*`.
    #[must_use]
    pub fn local_prefix(self) -> &'static str {
        match self {
            ArtifactKind::Postgres => "talos-",
            ArtifactKind::Vault => "vault-",
            ArtifactKind::Neo4j => "neo4j-",
        }
    }

    /// Local filename suffix written by `scripts/dev-backup/*`.
    #[must_use]
    pub fn local_suffix(self) -> &'static str {
        match self {
            ArtifactKind::Postgres => ".dump",
            ArtifactKind::Vault => ".tar.gz",
            // NOT unique to this kind — vault ends `.tar.gz` too. The
            // discriminators are `local_prefix` and `backup_subdir`; see the
            // module tests `two_targz_kinds_are_never_confused` and
            // `a_manifest_sibling_is_not_an_artifact`.
            ArtifactKind::Neo4j => ".tar.gz",
        }
    }
}

impl fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A UTC wall-clock stamp, to the second. Deliberately NOT a `chrono`
/// `DateTime` in the key path: the key must be a pure textual function of
/// the sidecar's filename, with no timezone, locale or leap-second
/// behaviour able to change it between two runs on the same file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stamp {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

impl Stamp {
    /// Parse the `YYYYMMDD-HHMMSS` form the backup sidecars emit
    /// (`date -u +%Y%m%d-%H%M%S`).
    #[must_use]
    pub fn parse_compact(s: &str) -> Option<Stamp> {
        let (d, t) = s.split_once('-')?;
        if d.len() != 8 || t.len() != 6 {
            return None;
        }
        if !d.bytes().all(|b| b.is_ascii_digit()) || !t.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n = |sl: &str| sl.parse::<u32>().ok();
        let st = Stamp {
            year: n(&d[0..4])? as i32,
            month: n(&d[4..6])?,
            day: n(&d[6..8])?,
            hour: n(&t[0..2])?,
            minute: n(&t[2..4])?,
            second: n(&t[4..6])?,
        };
        // Reject the obviously impossible rather than carrying it into a key.
        // This is a sanity gate, not a calendar: 2026-02-31 passes, and that
        // is fine — a filename the sidecar never wrote cannot be an artifact.
        if st.month == 0 || st.month > 12 || st.day == 0 || st.day > 31 {
            return None;
        }
        if st.hour > 23 || st.minute > 59 || st.second > 60 {
            return None;
        }
        Some(st)
    }

    /// The ISO-8601 basic form used inside object keys: `20260817T101757Z`.
    #[must_use]
    pub fn to_key_form(self) -> String {
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// Parse back out of [`Stamp::to_key_form`]. Used to age-check the
    /// artifacts that are already IN the bucket without downloading them.
    #[must_use]
    pub fn parse_key_form(s: &str) -> Option<Stamp> {
        if s.len() != 16 || !s.ends_with('Z') {
            return None;
        }
        let (d, rest) = s.split_at(8);
        let t = rest.strip_prefix('T')?.strip_suffix('Z')?;
        Stamp::parse_compact(&format!("{d}-{t}"))
    }

    /// Seconds since the Unix epoch, UTC. `None` for a calendar-invalid
    /// stamp (e.g. February 31st), which `parse_compact` deliberately lets
    /// through — the two checks answer different questions and only this one
    /// needs a real calendar.
    #[must_use]
    pub fn to_unix(self) -> Option<i64> {
        use chrono::{NaiveDate, TimeZone, Utc};
        let d = NaiveDate::from_ymd_opt(self.year, self.month, self.day)?;
        let dt = d.and_hms_opt(self.hour, self.minute, self.second.min(59))?;
        Utc.from_utc_datetime(&dt).timestamp().into()
    }
}

/// Why a local filename could not be turned into an object key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("filename '{0}' contains characters outside [A-Za-z0-9._-]")]
    UnsafeCharacters(String),
    #[error("filename '{0}' does not look like a {1} artifact (expected {2}<stamp>{3})")]
    WrongShape(String, &'static str, &'static str, &'static str),
    #[error("filename '{0}' carries no parseable YYYYMMDD-HHMMSS stamp")]
    NoStamp(String),
}

/// The single prefix everything this crate writes lives under. Versioned so
/// a future key-layout change is additive rather than ambiguous: a reader
/// can tell v1 keys from v2 keys without a manifest.
pub const KEY_ROOT: &str = "talos/v1";

/// Build the object key for one local artifact.
///
/// Shape: `talos/v1/<kind>/<YYYY>/<MM>/<YYYYMMDDTHHMMSSZ>-<kind>.age`
///
/// The `<YYYY>/<MM>` levels are not decoration — they keep a
/// `list-objects-v2` for "this month" cheap once the bucket has years of
/// daily archives in it, without the key itself carrying anything the flat
/// form did not.
///
/// Pure: no clock, no filesystem, no env. Given the same filename it always
/// returns the same key, which is what makes the "skip what already exists"
/// pass idempotent instead of duplicating on every run.
pub fn object_key(kind: ArtifactKind, local_filename: &str) -> Result<String, KeyError> {
    if local_filename.is_empty()
        || !local_filename
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(KeyError::UnsafeCharacters(local_filename.to_string()));
    }
    let stamp = stamp_of_local(kind, local_filename)?;
    Ok(format!(
        "{KEY_ROOT}/{kind}/{:04}/{:02}/{}-{kind}.age",
        stamp.year,
        stamp.month,
        stamp.to_key_form(),
    ))
}

/// Extract the stamp from a sidecar filename (`talos-20260817-101757.dump`).
pub fn stamp_of_local(kind: ArtifactKind, local_filename: &str) -> Result<Stamp, KeyError> {
    let mid = local_filename
        .strip_prefix(kind.local_prefix())
        .and_then(|s| s.strip_suffix(kind.local_suffix()))
        .ok_or_else(|| {
            KeyError::WrongShape(
                local_filename.to_string(),
                kind.as_str(),
                kind.local_prefix(),
                kind.local_suffix(),
            )
        })?;
    Stamp::parse_compact(mid).ok_or_else(|| KeyError::NoStamp(local_filename.to_string()))
}

/// Recover `(kind, stamp)` from an object key. The inverse of
/// [`object_key`], used to age-check the bucket's newest object from a
/// listing alone.
#[must_use]
pub fn parse_object_key(key: &str) -> Option<(ArtifactKind, Stamp)> {
    let rest = key.strip_prefix(KEY_ROOT)?.strip_prefix('/')?;
    let mut parts = rest.split('/');
    let kind = ArtifactKind::parse(parts.next()?)?;
    let _year = parts.next()?;
    let _month = parts.next()?;
    let file = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let stem = file
        .strip_suffix(".age")?
        .strip_suffix(kind.as_str())?
        .strip_suffix('-')?;
    let stamp = Stamp::parse_key_form(stem)?;
    Some((kind, stamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_derived_and_stable() {
        let a = object_key(ArtifactKind::Postgres, "talos-20260817-101757.dump").unwrap();
        let b = object_key(ArtifactKind::Postgres, "talos-20260817-101757.dump").unwrap();
        assert_eq!(a, b, "the same artifact must always map to the same key");
        assert_eq!(a, "talos/v1/postgres/2026/08/20260817T101757Z-postgres.age");
    }

    #[test]
    fn vault_key_uses_its_own_prefix_and_suffix() {
        let k = object_key(ArtifactKind::Vault, "vault-20260802-221124.tar.gz").unwrap();
        assert_eq!(k, "talos/v1/vault/2026/08/20260802T221124Z-vault.age");
    }

    #[test]
    fn distinct_dumps_never_share_a_key() {
        // The property "never overwrite" starts here: if two artifacts could
        // map to one key, a PUT of the second would destroy the first no
        // matter what the credential is allowed to do.
        let names = [
            "talos-20260817-101757.dump",
            "talos-20260817-101758.dump",
            "talos-20260818-101757.dump",
            "talos-20270817-101757.dump",
        ];
        let mut keys: Vec<String> = names
            .iter()
            .map(|n| object_key(ArtifactKind::Postgres, n).unwrap())
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), names.len());
    }

    #[test]
    fn kinds_never_collide_with_each_other() {
        let p = object_key(ArtifactKind::Postgres, "talos-20260817-101757.dump").unwrap();
        let v = object_key(ArtifactKind::Vault, "vault-20260817-101757.tar.gz").unwrap();
        let n = object_key(ArtifactKind::Neo4j, "neo4j-20260817-101757.tar.gz").unwrap();
        // Same second, same suffix for two of the three. The kind segment is
        // what keeps them apart, so a same-stamp vault and neo4j archive can
        // never PUT over one another.
        assert_ne!(p, v);
        assert_ne!(v, n);
        assert_ne!(p, n);
    }

    #[test]
    fn key_carries_nothing_sensitive() {
        // A bucket listing is metadata. Assert the key is built ONLY from
        // the two things the bucket's existence already implies.
        let k = object_key(ArtifactKind::Postgres, "talos-20260817-101757.dump").unwrap();
        for forbidden in [
            "evanhelbig",
            "/Users",
            "home",
            "talos_db",
            "postgres://",
            "secret",
            "actor",
            "org",
        ] {
            assert!(
                !k.contains(forbidden),
                "object key '{k}' leaks '{forbidden}'"
            );
        }
        // Exhaustive, not just a deny-list: every character is from the
        // closed alphabet the format produces.
        assert!(k
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/.-".contains(&b)));
    }

    #[test]
    fn traversal_and_shell_metacharacters_are_refused() {
        for bad in [
            "../../etc/passwd",
            "talos-2026 08 17.dump",
            "talos-20260817-101757.dump;rm -rf /",
            "talos-$(whoami).dump",
            "",
        ] {
            assert!(
                object_key(ArtifactKind::Postgres, bad).is_err(),
                "'{bad}' must not produce a key"
            );
        }
    }

    #[test]
    fn wrong_family_is_refused_rather_than_mislabelled() {
        // Filing a vault tarball under `postgres/` would make the drill
        // restore a tar with pg_restore and blame the backup.
        let e = object_key(ArtifactKind::Postgres, "vault-20260802-221124.tar.gz").unwrap_err();
        assert!(matches!(e, KeyError::WrongShape(..)), "got {e:?}");
    }

    #[test]
    fn partial_files_are_refused() {
        // `dev-backup-loop.sh` writes `<name>.partial` and renames. A
        // half-written dump must never be encrypted and shipped as if it
        // were a backup.
        assert!(object_key(ArtifactKind::Postgres, "talos-20260817-101757.dump.partial").is_err());
    }

    #[test]
    fn key_round_trips() {
        for (kind, name) in [
            (ArtifactKind::Postgres, "talos-20260817-101757.dump"),
            (ArtifactKind::Vault, "vault-20260802-221124.tar.gz"),
            (ArtifactKind::Neo4j, "neo4j-20260825-145720.tar.gz"),
        ] {
            let k = object_key(kind, name).unwrap();
            let (got_kind, got_stamp) = parse_object_key(&k).expect("round trip");
            assert_eq!(got_kind, kind);
            assert_eq!(got_stamp, stamp_of_local(kind, name).unwrap());
        }
    }

    #[test]
    fn foreign_keys_do_not_parse() {
        for bad in [
            "talos/v1/postgres/2026/08/nope.age",
            "talos/v2/postgres/2026/08/20260817T101757Z-postgres.age",
            // `neo4j` used to be the unknown-kind case here. It is a real
            // kind as of 2026-08-26, so the unknown-kind case moved to a
            // family that genuinely does not exist. If THIS one ever starts
            // parsing, the same review question applies: was a kind added
            // without walking `ArtifactKind::ALL`'s consumers?
            "talos/v1/redis/2026/08/20260817T101757Z-redis.age",
            "talos/v1/postgres/2026/08/20260817T101757Z-postgres.age/extra",
            "20260817T101757Z-postgres.age",
        ] {
            assert!(parse_object_key(bad).is_none(), "'{bad}' should not parse");
        }
    }

    #[test]
    fn all_is_pinned_and_exhaustive() {
        // Deliberately HAND-WRITTEN, not derived from `ALL`. Every other
        // assertion about kinds in this crate iterates `ArtifactKind::ALL`
        // on both sides, which makes them self-adjusting and therefore
        // useless as a guard on `ALL` itself: a variant added to the enum
        // but forgotten in `ALL` would leave all of them green while the
        // artifact was never discovered, never planned and never pre-seeded.
        // This is the one place that would go red.
        assert_eq!(ArtifactKind::ALL.len(), 3);
        let got: Vec<&str> = ArtifactKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(got, ["postgres", "vault", "neo4j"]);

        // These &strs are Prometheus label VALUES and object-key path
        // segments. Renaming one splits a counter in two, orphans every
        // dashboard on the old name, AND makes every already-uploaded object
        // of that kind unreachable by `parse_object_key`.
        let mut sorted = got.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), got.len(), "label values must be unique");
    }

    #[test]
    fn every_kind_round_trips_through_its_label() {
        // Closes the `parse`/`as_str` pair: `parse` matches on `&str` with a
        // `_ => None` arm, so a missing arm compiles. A kind that does not
        // round-trip would be dropped by `MetricState::carried_forward`,
        // silently resetting its counters on every run.
        for k in ArtifactKind::ALL {
            assert_eq!(ArtifactKind::parse(k.as_str()), Some(k), "{k}");
        }
        assert_eq!(ArtifactKind::parse("nonsense"), None);
    }

    #[test]
    fn a_manifest_sibling_is_not_an_artifact() {
        // Every tarball on disk has a `<name>.tar.gz.manifest` beside it
        // (13 of each for vault AND neo4j on the dev host). A `contains`
        // style suffix test would classify the 500-byte manifest as an
        // archive and ship it under the tarball's own key shape.
        // `strip_suffix` is an exact tail match, so it does not.
        for (kind, name) in [
            (ArtifactKind::Vault, "vault-20260825-145654.tar.gz.manifest"),
            (ArtifactKind::Neo4j, "neo4j-20260825-145720.tar.gz.manifest"),
        ] {
            assert!(
                object_key(kind, name).is_err(),
                "{name} must not become an object key"
            );
            assert!(stamp_of_local(kind, name).is_err());
        }
    }

    #[test]
    fn two_targz_kinds_are_never_confused() {
        // `local_suffix` is `.tar.gz` for BOTH vault and neo4j, so it cannot
        // be the discriminator. Two independent guards keep them apart, and
        // this asserts the second one — the prefix — in isolation, because
        // the first (one directory per `backup_subdir`) lives in
        // `discover_local` and would not protect a misplaced file.
        assert!(object_key(ArtifactKind::Vault, "neo4j-20260825-145720.tar.gz").is_err());
        assert!(object_key(ArtifactKind::Neo4j, "vault-20260825-145654.tar.gz").is_err());
        // And the directories really are disjoint, so guard 1 is not a
        // no-op either.
        assert_ne!(
            ArtifactKind::Vault.backup_subdir(),
            ArtifactKind::Neo4j.backup_subdir()
        );
        assert_ne!(
            ArtifactKind::Vault.local_prefix(),
            ArtifactKind::Neo4j.local_prefix()
        );

        // A same-second pair filed under the right kinds lands in different
        // key namespaces, so neither can overwrite the other.
        let v = object_key(ArtifactKind::Vault, "vault-20260825-145720.tar.gz").unwrap();
        let n = object_key(ArtifactKind::Neo4j, "neo4j-20260825-145720.tar.gz").unwrap();
        assert_eq!(v, "talos/v1/vault/2026/08/20260825T145720Z-vault.age");
        assert_eq!(n, "talos/v1/neo4j/2026/08/20260825T145720Z-neo4j.age");

        // Round-tripping a key must recover the kind it was filed under, not
        // merely "some .tar.gz kind".
        assert_eq!(parse_object_key(&v).unwrap().0, ArtifactKind::Vault);
        assert_eq!(parse_object_key(&n).unwrap().0, ArtifactKind::Neo4j);
    }

    #[test]
    fn a_neo4j_partial_is_refused_like_every_other_kind() {
        assert!(object_key(ArtifactKind::Neo4j, "neo4j-20260825-145720.tar.gz.partial").is_err());
        assert!(object_key(ArtifactKind::Neo4j, "neo4j-20260825-145720.tar").is_err());
        assert!(object_key(ArtifactKind::Neo4j, "neo4j-.tar.gz").is_err());
    }

    #[test]
    fn stamp_rejects_junk() {
        for bad in [
            "2026081-101757",
            "20260817-10175",
            "20260817101757",
            "2026aa17-101757",
            "20261317-101757",
            "20260800-101757",
            "20260817-241757",
        ] {
            assert!(Stamp::parse_compact(bad).is_none(), "'{bad}' parsed");
        }
    }

    #[test]
    fn stamp_to_unix_is_utc_and_rejects_impossible_calendar_days() {
        let s = Stamp::parse_compact("20260817-101757").unwrap();
        // 2026-08-17T10:17:57Z. Cross-checked against
        // `date -u -d @1786961877` rather than derived from the same code
        // that is under test.
        assert_eq!(s.to_unix(), Some(1_786_961_877));
        let feb31 = Stamp::parse_compact("20260231-000000").unwrap();
        assert_eq!(feb31.to_unix(), None);
    }
}

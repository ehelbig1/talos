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
/// `neo4j` is deliberately ABSENT. The graph is reconstructible from
/// `actor_memory` via `graph_backfill`, so paying egress and a second fatal
/// secret's blast radius for it is not worth it. That is a judgement, not an
/// oversight — if the graph ever stops being reconstructible, add it here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArtifactKind {
    /// `pg_dump --format=custom` of the whole database.
    Postgres,
    /// Opaque tar of Vault's file backend (`/vault/file`).
    Vault,
}

impl ArtifactKind {
    /// Every kind, in a stable order. Closed set — the metric label values
    /// are pre-seeded from this, so `increase(...) > 0` is well-defined
    /// before the first upload ever happens.
    pub const ALL: [ArtifactKind; 2] = [ArtifactKind::Postgres, ArtifactKind::Vault];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Postgres => "postgres",
            ArtifactKind::Vault => "vault",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "postgres" => Some(ArtifactKind::Postgres),
            "vault" => Some(ArtifactKind::Vault),
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
        }
    }

    /// Local filename prefix written by `scripts/dev-backup/*`.
    #[must_use]
    pub fn local_prefix(self) -> &'static str {
        match self {
            ArtifactKind::Postgres => "talos-",
            ArtifactKind::Vault => "vault-",
        }
    }

    /// Local filename suffix written by `scripts/dev-backup/*`.
    #[must_use]
    pub fn local_suffix(self) -> &'static str {
        match self {
            ArtifactKind::Postgres => ".dump",
            ArtifactKind::Vault => ".tar.gz",
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
        assert_ne!(p, v);
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
            "talos/v1/neo4j/2026/08/20260817T101757Z-neo4j.age",
            "talos/v1/postgres/2026/08/20260817T101757Z-postgres.age/extra",
            "20260817T101757Z-postgres.age",
        ] {
            assert!(parse_object_key(bad).is_none(), "'{bad}' should not parse");
        }
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

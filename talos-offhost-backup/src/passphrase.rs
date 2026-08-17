//! Where the `age` passphrase may come from.
//!
//! # This is a SECOND fatal secret
//!
//! Tier 1 escrowed the master KEK. This change adds a second key whose loss
//! is equally total: **lose the `age` passphrase and every archive in the
//! bucket is unreadable forever**, exactly as if the KEK had been lost. It
//! is not a lesser secret because it is newer, and it needs the same
//! containment #639 gave the KEK — which is why the rules below are the same
//! rules, not similar ones:
//!
//! * exactly one source; setting both is REFUSED rather than resolved by a
//!   precedence rule the operator cannot see (the branch that loses is
//!   always the one carrying the checks);
//! * a source that resolves inside a checkout is refused — a checkout leaks
//!   into container image layers and into `git add -f`;
//! * a source that resolves inside `$BACKUP_DIR` is refused — whoever steals
//!   the archives would then also hold the key that opens them, which makes
//!   the encryption decorative;
//! * symlinks are resolved BEFORE the check, because
//!   `cd "$(dirname f)" && pwd -P` resolves a symlinked DIRECTORY and not a
//!   symlinked FILE, and that gap was found by testing the bypass rather
//!   than by reading the code.
//!
//! # What is NOT established here
//!
//! The same limits #639 states, for the same reasons. This cannot tell that
//! `/Volumes/escrow` is a RAM disk, that a password-manager vault syncs to
//! this same laptop, or that a **hard link** inside a checkout points at a
//! file outside it — a hard link is a genuinely different path with no
//! symlink to resolve, so canonicalisation cannot see through it. These are
//! specific holes closed, not a proof of provenance.
//!
//! # Rotation
//!
//! A rotated passphrase opens the OLD archives and not the new ones, and the
//! reverse. The 1Password entry must therefore record WHICH archives each
//! passphrase opens (by object-key date range), or a future recovery has the
//! right secret for the wrong half of the bucket. That is the same trap the
//! KEK entry carries and it is documented in `docs/offhost-backup.md`.

use std::path::{Path, PathBuf};

/// Which source the passphrase came from. Carries no secret material — this
/// is what may be logged.
///
/// `Debug` is HAND-ROLLED, not derived. The `Command` variant holds a shell
/// command that routinely names a vault item (`op read "op://Private/…"`),
/// and a careless setup can put the passphrase itself in it (`echo hunter2`).
/// [`PassphraseSource::describe`] already refuses to print it; a derived
/// `Debug` would print it anyway the first time anyone writes `{:?}` in a
/// diagnostic, which is precisely the accident the describe() method exists
/// to prevent.
#[derive(Clone, PartialEq, Eq)]
pub enum PassphraseSource {
    /// A command whose stdout is the passphrase. Preferred: it never lands
    /// on disk. e.g. `op read "op://Private/Talos age backup/password"`.
    Command(String),
    /// A file whose first line is the passphrase, on off-box media.
    File(PathBuf),
}

impl std::fmt::Debug for PassphraseSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

impl PassphraseSource {
    /// A description safe to print. Deliberately not `Display` on a type
    /// that could ever hold the secret itself.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            PassphraseSource::Command(_) => {
                // The command line is NOT printed. It routinely contains a
                // vault item reference, and a reference plus a stolen
                // session is most of the way to the secret.
                "TALOS_OFFHOST_AGE_PASSPHRASE_CMD".to_string()
            }
            PassphraseSource::File(p) => {
                format!("TALOS_OFFHOST_AGE_PASSPHRASE_FILE ({})", p.display())
            }
        }
    }
}

/// Why a configured passphrase source was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceRejection {
    #[error(
        "both TALOS_OFFHOST_AGE_PASSPHRASE_CMD and TALOS_OFFHOST_AGE_PASSPHRASE_FILE are set.\n   \
         Resolving that by precedence would silently ignore one of them — and the one that \
         loses is the FILE, the branch that carries the containment checks. Unset whichever \
         you did not mean."
    )]
    BothSet,
    #[error(
        "no age passphrase source configured. Set exactly one of\n   \
         TALOS_OFFHOST_AGE_PASSPHRASE_CMD='op read \"op://Private/Talos age backup/password\"'\n   \
         TALOS_OFFHOST_AGE_PASSPHRASE_FILE=/Volumes/escrow/talos-age.pass"
    )]
    NotConfigured,
    #[error(
        "{what} resolves to '{path}', INSIDE a checkout ({root}).\n   \
         The passphrase must not live where the code lives — a checkout, a container image \
         layer or a stray `git add -f` then carries it. Move it off-box."
    )]
    InsideCheckout {
        what: String,
        path: String,
        root: String,
    },
    #[error(
        "{what} resolves to '{path}', INSIDE the backup directory ({root}).\n   \
         Whoever steals the archives then also has the key that unlocks them, which makes the \
         encryption decorative. Keep the passphrase on a different medium."
    )]
    InsideBackupDir {
        what: String,
        path: String,
        root: String,
    },
    #[error("the configured passphrase source produced an EMPTY passphrase")]
    Empty,
}

/// Pick the single configured source, refusing both-set and neither-set.
///
/// Empty strings count as unset: `export FOO=` in a shell profile is how an
/// operator disables one, and treating it as "set to nothing" would fail
/// with the wrong message.
pub fn choose_source(
    cmd: Option<&str>,
    file: Option<&str>,
) -> Result<PassphraseSource, SourceRejection> {
    let cmd = cmd.filter(|s| !s.trim().is_empty());
    let file = file.filter(|s| !s.trim().is_empty());
    match (cmd, file) {
        (Some(_), Some(_)) => Err(SourceRejection::BothSet),
        (Some(c), None) => Ok(PassphraseSource::Command(c.to_string())),
        (None, Some(f)) => Ok(PassphraseSource::File(PathBuf::from(f))),
        (None, None) => Err(SourceRejection::NotConfigured),
    }
}

/// Refuse a path that resolves under a checkout or under the backup
/// directory.
///
/// `resolved` must ALREADY be canonicalised by the caller (symlinks
/// resolved); this function is pure so it is testable without a filesystem,
/// and taking an un-resolved path would make it trivially bypassable by a
/// symlink — the exact bypass #639 found by testing rather than by reading.
pub fn assert_contained(
    resolved: &Path,
    what: &str,
    checkout_roots: &[PathBuf],
    backup_dir: Option<&Path>,
) -> Result<(), SourceRejection> {
    for root in checkout_roots {
        if under(resolved, root) {
            return Err(SourceRejection::InsideCheckout {
                what: what.to_string(),
                path: resolved.display().to_string(),
                root: root.display().to_string(),
            });
        }
    }
    if let Some(b) = backup_dir {
        if under(resolved, b) {
            return Err(SourceRejection::InsideBackupDir {
                what: what.to_string(),
                path: resolved.display().to_string(),
                root: b.display().to_string(),
            });
        }
    }
    Ok(())
}

fn under(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

/// Every whitespace-separated token of a command that LOOKS like a path.
///
/// STATED LIMIT, copied verbatim in spirit from #639: this is a token scan,
/// not a shell parser. `TALOS_OFFHOST_AGE_PASSPHRASE_CMD="cat <repo>/.pass"`
/// must be refused the same way the `_FILE` form is — the guarded branch
/// being the one nobody is told to use is how the check ends up decorative.
/// A path assembled from a variable, built inside a helper script, or
/// reached through a hard link is invisible to it.
#[must_use]
pub fn path_like_tokens(cmd: &str) -> Vec<String> {
    cmd.split_whitespace()
        .map(|t| t.trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|t| t.contains('/'))
        .collect()
}

/// Reject an obviously-empty passphrase before it produces an archive that
/// anyone can open.
pub fn assert_non_empty(passphrase: &str) -> Result<(), SourceRejection> {
    if passphrase.trim().is_empty() {
        return Err(SourceRejection::Empty);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/Users/x/projects/talos"),
            PathBuf::from("/Users/x/projects/talos/.claude/worktrees/wt"),
        ]
    }

    #[test]
    fn both_set_is_refused_not_resolved_by_precedence() {
        // The FILE branch is the one carrying the containment checks, so a
        // silent precedence rule hands the operator the UNGUARDED source
        // without telling them.
        assert_eq!(
            choose_source(Some("op read x"), Some("/Volumes/escrow/p")),
            Err(SourceRejection::BothSet)
        );
    }

    #[test]
    fn neither_set_is_an_error_with_an_actionable_message() {
        let e = choose_source(None, None).unwrap_err();
        assert_eq!(e, SourceRejection::NotConfigured);
        let msg = e.to_string();
        assert!(msg.contains("TALOS_OFFHOST_AGE_PASSPHRASE_CMD"));
        assert!(msg.contains("TALOS_OFFHOST_AGE_PASSPHRASE_FILE"));
    }

    #[test]
    fn empty_env_vars_count_as_unset() {
        assert_eq!(
            choose_source(Some("   "), Some("/Volumes/escrow/p")),
            Ok(PassphraseSource::File(PathBuf::from("/Volumes/escrow/p")))
        );
        assert_eq!(
            choose_source(Some(""), Some("")),
            Err(SourceRejection::NotConfigured)
        );
    }

    #[test]
    fn a_passphrase_inside_the_checkout_is_refused() {
        let e = assert_contained(
            Path::new("/Users/x/projects/talos/.age.pass"),
            "passphrase file",
            &roots(),
            None,
        )
        .unwrap_err();
        assert!(matches!(e, SourceRejection::InsideCheckout { .. }), "{e:?}");
    }

    #[test]
    fn the_main_clone_counts_when_running_from_a_worktree() {
        // #639's exact bug: `${BASH_SOURCE[0]}/../..` resolves to the
        // WORKTREE root, whose subtree does not contain the main clone — so
        // a key file sitting in the main checkout was ACCEPTED. Both roots
        // must be supplied and both must be checked.
        let e = assert_contained(
            Path::new("/Users/x/projects/talos/secrets/age.pass"),
            "passphrase file",
            &roots(),
            None,
        );
        assert!(e.is_err(), "the main clone must be refused from a worktree");
    }

    #[test]
    fn a_passphrase_inside_the_backup_dir_is_refused() {
        let e = assert_contained(
            Path::new("/Users/x/.talos/backups/age.pass"),
            "passphrase file",
            &roots(),
            Some(Path::new("/Users/x/.talos/backups")),
        )
        .unwrap_err();
        assert!(
            matches!(e, SourceRejection::InsideBackupDir { .. }),
            "the key must not sit beside the ciphertext it opens: {e:?}"
        );
    }

    #[test]
    fn the_backup_dir_itself_is_refused_not_just_its_children() {
        assert!(assert_contained(
            Path::new("/Users/x/.talos/backups"),
            "passphrase file",
            &[],
            Some(Path::new("/Users/x/.talos/backups")),
        )
        .is_err());
    }

    #[test]
    fn a_sibling_directory_with_a_shared_prefix_is_allowed() {
        // `/Users/x/.talos/backups-elsewhere` is NOT under
        // `/Users/x/.talos/backups`. A naive string `starts_with` on the
        // rendered path would refuse it; `Path::starts_with` is
        // component-wise, which is why it is used.
        assert!(assert_contained(
            Path::new("/Users/x/.talos/backups-elsewhere/age.pass"),
            "passphrase file",
            &roots(),
            Some(Path::new("/Users/x/.talos/backups")),
        )
        .is_ok());
    }

    #[test]
    fn off_box_media_is_allowed() {
        assert!(assert_contained(
            Path::new("/Volumes/escrow/talos-age.pass"),
            "passphrase file",
            &roots(),
            Some(Path::new("/Users/x/.talos/backups")),
        )
        .is_ok());
    }

    #[test]
    fn a_command_reading_a_repo_path_is_visible_to_the_token_scan() {
        // The guarded branch must not be the one nobody is told to use.
        let toks = path_like_tokens("cat /Users/x/projects/talos/.age.pass");
        assert_eq!(toks, vec!["/Users/x/projects/talos/.age.pass"]);
        for t in &toks {
            assert!(assert_contained(Path::new(t), "cmd arg", &roots(), None).is_err());
        }
    }

    #[test]
    fn token_scan_strips_quotes_and_ignores_non_paths() {
        let toks = path_like_tokens("op read \"op://Private/Talos age backup/password\"");
        // STATED LIMIT, demonstrated rather than described: this splits on
        // WHITESPACE, so a quoted argument containing spaces becomes two
        // tokens. Neither fragment exists on disk, so the caller skips both
        // — harmless here, and the honest reason it is harmless is that a
        // token scan is not a shell parser, not that it parsed correctly.
        assert_eq!(toks, vec!["op://Private/Talos", "backup/password"]);
        assert!(path_like_tokens("some-helper --flag value").is_empty());
    }

    #[test]
    fn debug_is_the_redacted_description_not_the_command() {
        // A derived Debug would print the command the first time anyone
        // writes `{:?}` in a diagnostic — which is exactly what describe()
        // exists to prevent, so the two must not disagree.
        let s = PassphraseSource::Command("echo hunter2-unique-marker".into());
        let d = format!("{s:?}");
        assert!(!d.contains("hunter2-unique-marker"), "{d}");
        assert_eq!(d, s.describe());
    }

    #[test]
    fn the_source_description_never_carries_the_command_text() {
        // A vault item reference plus a stolen session is most of the way to
        // the secret, so the command line is not logged either.
        let s =
            PassphraseSource::Command("op read \"op://Private/Talos age backup/password\"".into());
        let d = s.describe();
        assert!(!d.contains("op://"));
        assert!(!d.contains("password"));
        assert!(d.contains("TALOS_OFFHOST_AGE_PASSPHRASE_CMD"));
    }

    #[test]
    fn an_empty_passphrase_is_refused() {
        assert_eq!(assert_non_empty(""), Err(SourceRejection::Empty));
        assert_eq!(assert_non_empty("  \n "), Err(SourceRejection::Empty));
        assert!(assert_non_empty("correct horse battery staple").is_ok());
    }
}

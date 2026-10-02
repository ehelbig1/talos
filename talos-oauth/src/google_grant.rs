//! Which of a user's connections share one Google account's grant.
//!
//! Google keeps ONE grant per (Google account, OAuth client). Every Google
//! integration here uses the same client, and `oauth2.googleapis.com/revoke`
//! ends the whole grant: seen live 2026-10-02, disconnecting Health on an
//! account returned 401 on that account's Calendar token two minutes later.
//! So a disconnect may revoke at Google only when no OTHER connection is on
//! the same Google account.
//!
//! "Same account" is decided from what each connection stores:
//! * Calendar, Cloud and Health key a connection by a UUID derived from the
//!   Google account id, by the same arithmetic — equal keys are one account.
//! * Gmail keys a connection by its address; the others store the address as
//!   `account_email`.
//!
//! A connection whose account cannot be identified is counted as POSSIBLY
//! shared. Withholding a revoke leaves a grant at Google that nothing here
//! holds a token for; revoking a shared grant takes working connections down.

/// One active Google credential of a user, with the account address when the
/// integration's own table records one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoogleConnection {
    pub provider: String,
    pub provider_key: String,
    /// Lower-cased account address; `None` when it is not recorded.
    pub email: Option<String>,
}

impl GoogleConnection {
    fn is_gmail(&self) -> bool {
        self.provider == "gmail"
    }
    /// Gmail's key IS its address.
    fn address(&self) -> Option<String> {
        if self.is_gmail() {
            Some(self.provider_key.to_lowercase())
        } else {
            self.email.as_ref().map(|e| e.to_lowercase())
        }
    }
}

/// How one connection relates to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    SameAccount,
    OtherAccount,
    /// The account of one side is not recorded.
    Unidentified,
}

fn relation(this: &GoogleConnection, other: &GoogleConnection) -> Relation {
    if this.provider_key.eq_ignore_ascii_case(&other.provider_key) {
        return Relation::SameAccount;
    }
    match (this.address(), other.address()) {
        (Some(a), Some(b)) if a == b => Relation::SameAccount,
        (Some(_), Some(_)) => Relation::OtherAccount,
        // Two derived keys that differ are two Google account ids. An address
        // is only NEEDED to relate a Gmail connection to a non-Gmail one.
        _ if !this.is_gmail() && !other.is_gmail() => Relation::OtherAccount,
        _ => Relation::Unidentified,
    }
}

/// Whether revoking `this` connection's token at Google could end other
/// connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantSharing {
    /// No other active connection is, or may be, on this Google account.
    Sole,
    /// `same_account` others are on this account; `unidentified` others could
    /// not be placed and are treated as if they were.
    Shared {
        same_account: usize,
        unidentified: usize,
    },
}

impl GrantSharing {
    pub(crate) fn revoke_would_end_other_connections(self) -> bool {
        matches!(self, GrantSharing::Shared { .. })
    }
}

/// Classify `this` against the user's OTHER active Google connections.
pub(crate) fn grant_sharing(this: &GoogleConnection, others: &[GoogleConnection]) -> GrantSharing {
    let (mut same_account, mut unidentified) = (0usize, 0usize);
    for other in others {
        match relation(this, other) {
            Relation::SameAccount => same_account += 1,
            Relation::Unidentified => unidentified += 1,
            Relation::OtherAccount => {}
        }
    }
    if same_account == 0 && unidentified == 0 {
        GrantSharing::Sole
    } else {
        GrantSharing::Shared {
            same_account,
            unidentified,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(provider: &str, key: &str, email: Option<&str>) -> GoogleConnection {
        GoogleConnection {
            provider: provider.into(),
            provider_key: key.into(),
            email: email.map(str::to_string),
        }
    }
    const K1: &str = "63012854-b3ac-dc54-301c-7b5cc9aff819";
    const K2: &str = "f6da2c8c-377b-bf4a-5454-3bfa6e50ac73";

    #[test]
    fn a_connection_with_no_others_is_sole() {
        assert_eq!(
            grant_sharing(&conn("google_health", K1, Some("a@x.test")), &[]),
            GrantSharing::Sole
        );
    }

    #[test]
    fn equal_derived_keys_are_one_account_even_without_addresses() {
        let this = conn("google_health", K1, None);
        let others = [conn("google_calendar", K1, None)];
        assert_eq!(
            grant_sharing(&this, &others),
            GrantSharing::Shared {
                same_account: 1,
                unidentified: 0
            }
        );
    }

    #[test]
    fn different_derived_keys_are_different_accounts() {
        let this = conn("google_health", K1, None);
        let others = [
            conn("google_calendar", K2, None),
            conn("google_cloud", K2, Some("b@x.test")),
        ];
        assert_eq!(grant_sharing(&this, &others), GrantSharing::Sole);
    }

    #[test]
    fn equal_addresses_are_one_account_even_when_the_keys_differ() {
        // Guards a derivation that drifts between integrations.
        let this = conn("google_health", K1, Some("a@x.test"));
        let others = [conn("google_calendar", K2, Some("A@X.test"))];
        assert!(grant_sharing(&this, &others).revoke_would_end_other_connections());
    }

    #[test]
    fn gmail_is_related_to_the_others_by_address() {
        let gmail = conn("gmail", "A@x.test", None);
        let same = conn("google_calendar", K1, Some("a@x.test"));
        let other = conn("google_calendar", K2, Some("b@x.test"));
        assert_eq!(
            grant_sharing(&gmail, &[same.clone(), other.clone()]),
            GrantSharing::Shared {
                same_account: 1,
                unidentified: 0
            }
        );
        assert_eq!(grant_sharing(&gmail, &[other.clone()]), GrantSharing::Sole);
        // And from the other side.
        assert!(grant_sharing(&same, &[gmail.clone()]).revoke_would_end_other_connections());
        assert_eq!(grant_sharing(&other, &[gmail]), GrantSharing::Sole);
    }

    #[test]
    fn two_gmail_connections_are_two_accounts() {
        let this = conn("gmail", "a@x.test", None);
        assert_eq!(
            grant_sharing(&this, &[conn("gmail", "b@x.test", None)]),
            GrantSharing::Sole
        );
    }

    #[test]
    fn a_connection_that_cannot_be_placed_counts_as_possibly_shared() {
        // Gmail against a connection with no recorded address, both ways.
        let gmail = conn("gmail", "a@x.test", None);
        let unknown = conn("google_calendar", K1, None);
        assert_eq!(
            grant_sharing(&gmail, &[unknown.clone()]),
            GrantSharing::Shared {
                same_account: 0,
                unidentified: 1
            }
        );
        assert_eq!(
            grant_sharing(&unknown, &[gmail]),
            GrantSharing::Shared {
                same_account: 0,
                unidentified: 1
            }
        );
    }
}

//! The password hash of an account that has no password.
//!
//! `users.password_hash` is `NOT NULL`, so an account created without a
//! password (an OAuth sign-up, a synthetic MCP-agent user, the local dev
//! user) still needs a value there. That value must satisfy two properties
//! at once, and each earlier attempt kept one and dropped the other:
//!
//! * **Nothing verifies against it.** Until 2026-09-18 an OAuth sign-up
//!   stored `bcrypt(`[`LEGACY_OAUTH_NO_PASSWORD_SENTINEL`]`)` under a
//!   comment claiming "bcrypt::verify returns false, never true". It
//!   returns TRUE for that literal, and the literal is in this public
//!   repository, so anyone who knew the email of an OAuth-created account
//!   could sign in to it with that string as the password.
//! * **It is a structurally valid bcrypt hash at the deployment's cost**, so
//!   a login attempt against it pays the full verify cost and returns
//!   `Ok(false)` rather than an instant `Err` — otherwise response timing
//!   tells an attacker which accounts have no password (MCP-709, MCP-1083).
//!
//! [`unusable_password_hash`] is bcrypt of 32 bytes from the operating
//! system's CSPRNG, generated per call and never stored, logged or returned.
//! Rows written before this crate existed may still hold the legacy
//! sentinel's hash; [`is_reserved_password`] names the one password that
//! verifies against them, and every password check refuses it.

use rand::RngCore;
use zeroize::Zeroizing;

/// The literal whose bcrypt hash OAuth sign-ups stored until 2026-09-18.
/// Rows created then still verify against it; it must never be accepted as
/// a password, and it can never be chosen as one.
pub const LEGACY_OAUTH_NO_PASSWORD_SENTINEL: &str = "__talos_oauth_account_no_password__";

/// Bytes of CSPRNG output behind each unusable hash: 256 bits, far past any
/// brute force, and 64 hex characters, inside bcrypt's 72-byte input limit.
const SEED_BYTES: usize = 32;

/// A bcrypt hash, at `cost`, that no password verifies against.
///
/// # Errors
/// Only if bcrypt rejects `cost` (outside 4..=31).
pub fn unusable_password_hash(cost: u32) -> Result<String, bcrypt::BcryptError> {
    let mut seed = Zeroizing::new([0u8; SEED_BYTES]);
    rand::rngs::OsRng.fill_bytes(seed.as_mut());
    let mut hex = Zeroizing::new(String::with_capacity(SEED_BYTES * 2));
    for b in seed.iter() {
        hex.push(char::from(HEX[usize::from(b >> 4)]));
        hex.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    bcrypt::hash(hex.as_bytes(), cost)
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// True for a password that must be refused wherever a password is checked
/// or chosen: today, only the legacy OAuth sentinel.
#[must_use]
pub fn is_reserved_password(password: &str) -> bool {
    password == LEGACY_OAUTH_NO_PASSWORD_SENTINEL
}

#[cfg(test)]
mod tests {
    use super::*;

    const COST: u32 = 4;

    /// The defect this crate exists for, stated as a fact about bcrypt: the
    /// legacy sentinel DOES verify against its own hash. If this ever fails,
    /// bcrypt changed, not the risk.
    #[test]
    fn the_legacy_sentinel_verifies_against_its_own_hash() {
        let legacy = bcrypt::hash(LEGACY_OAUTH_NO_PASSWORD_SENTINEL, COST).unwrap();
        assert!(bcrypt::verify(LEGACY_OAUTH_NO_PASSWORD_SENTINEL, &legacy).unwrap());
    }

    #[test]
    fn nothing_verifies_against_an_unusable_hash() {
        let h = unusable_password_hash(COST).unwrap();
        for candidate in [
            LEGACY_OAUTH_NO_PASSWORD_SENTINEL,
            "",
            "password",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            assert!(
                matches!(bcrypt::verify(candidate, &h), Ok(false)),
                "{candidate:?} must be Ok(false), not a match and not an Err"
            );
        }
    }

    #[test]
    fn the_hash_is_well_formed_at_the_requested_cost() {
        let h = unusable_password_hash(COST).unwrap();
        assert_eq!(h.len(), 60, "a bcrypt hash is 60 characters");
        assert!(
            h.starts_with("$2b$04$"),
            "cost must be the requested one: {h}"
        );
    }

    #[test]
    fn every_call_draws_a_fresh_seed() {
        // Distinct salts alone would make two hashes differ; what matters is
        // that the SEED differs, i.e. no hash verifies the other's preimage.
        // Two hashes of one seed would make both verify it; this can only be
        // observed indirectly, so pin the output differs and neither is a
        // hash of an all-zero seed (a fill_bytes that never ran).
        let a = unusable_password_hash(COST).unwrap();
        let b = unusable_password_hash(COST).unwrap();
        assert_ne!(a, b);
        let zero_seed = "0".repeat(SEED_BYTES * 2);
        assert!(!bcrypt::verify(&zero_seed, &a).unwrap());
    }

    #[test]
    fn only_the_legacy_sentinel_is_reserved() {
        assert!(is_reserved_password(LEGACY_OAUTH_NO_PASSWORD_SENTINEL));
        assert!(!is_reserved_password("__talos_oauth_account_no_password_"));
        assert!(!is_reserved_password(""));
    }

    #[test]
    fn a_bad_cost_is_an_error() {
        assert!(unusable_password_hash(3).is_err());
    }
}

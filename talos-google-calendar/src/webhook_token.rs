//! Webhook token for Google Calendar push notifications.
//!
//! # Since 2026-10-14: a random per-channel token, hashed in the row
//!
//! Security review 2026-10-14, F-6: the token below was an HMAC under the
//! fleet-wide `WORKER_SHARED_KEY`, which every worker holds, so a worker could
//! mint a valid token for any `(user, channel)`. A channel created now carries
//!
//! ```text
//! token = base64url( user_id (16 bytes) || 32 random bytes )   — 64 chars
//! ```
//!
//! and its row stores only `token_hash` = hex SHA-256 of the token
//! ([`mint_channel_token`]). The user id stays in the token so the handler can
//! scope its row read to one user (integration_state is per-user); it is a
//! routing hint, not an authenticator. [`channel_token_admits`] decides,
//! after the row is read: a row with a hash admits only the token whose
//! SHA-256 it is (constant-time), and never a WSK-minted token.
//!
//! **The dual-verify window.** A row written before this change has no hash,
//! and its channel's token is the legacy HMAC. Such a row is still admitted
//! by the legacy check below until [`LEGACY_WSK_TOKENS_ACCEPTED_UNTIL_UNIX`]
//! (2026-12-01T00:00:00Z). Google channels live 7 days and are renewed at
//! < 24 h remaining, and a renewal mints a new channel with a hashed token, so
//! every live channel has moved over within a week of the deploy. After the
//! end date a legacy token is refused everywhere, and the legacy code below
//! is dead and should be deleted.
//!
//! # The legacy token (verified only inside the window)
//!
//! # Problem
//!
//! When a watch channel fires, Google POSTs to our `/api/google-calendar/
//! webhook` endpoint with these headers — and no body:
//!
//! - `X-Goog-Channel-ID`      — the UUID we supplied at channel create
//! - `X-Goog-Resource-ID`     — Google's opaque identifier for the resource
//! - `X-Goog-Channel-Token`   — the opaque verification token we supplied
//! - `X-Goog-Resource-State`  — "sync" or "exists"
//!
//! There is no user identifier. Historically, Talos stored watch
//! channels in a flat `google_calendar_watch_channels` table keyed by
//! `channel_id`, so one DB lookup sufficed to find the owning user.
//! With `integration_state` (scoped per `user_id` by design), that flat
//! lookup no longer exists — the webhook handler needs to recover the
//! `user_id` before it can read the channel row.
//!
//! # Solution
//!
//! Embed the `user_id` in the channel token, cryptographically bound to
//! the `google_channel_id`. The token is opaque to Google; we choose
//! its contents. Format:
//!
//! ```text
//! token = base64url( user_id (16 bytes)
//!                   || HMAC_SHA256(key, "gcal-webhook" || user_id || channel_id)
//!                         truncated to 16 bytes )
//! ```
//!
//! The HMAC key is the same `WORKER_SHARED_KEY` registered with
//! `rpc_auth` at controller startup.
//!
//! Properties:
//! - **Stateless**: no DB lookup to recover the user_id.
//! - **Unforgeable**: HMAC key is never sent off-host. An attacker
//!   cannot produce a valid `(user_id, channel_id)` pair without
//!   the key.
//! - **Channel-bound**: the HMAC covers the channel_id, so a token
//!   issued for channel A cannot be replayed onto channel B.
//! - **Constant-time verification**: the MAC compare uses
//!   `subtle::ConstantTimeEq` to avoid timing side-channels.
//! - **Size-bounded**: token is always 43 base64url bytes (no
//!   padding) — small enough for an HTTP header.

use subtle::ConstantTimeEq;
use uuid::Uuid;

/// HMAC tag is truncated to 16 bytes. Full SHA-256 is 32 bytes —
/// 128 bits of collision resistance is ample for a per-channel
/// webhook verifier (well above the ~80-bit threshold commonly
/// accepted for integrity tags). Cuts the header size in half.
const HMAC_TAG_LEN: usize = 16;

/// Domain separation string mixed into the HMAC input. Prevents a
/// token signed in one context (gcal-webhook) from being mistaken
/// for a signature in another (e.g. some other RPC that happens to
/// concatenate the same bytes).
const DOMAIN_TAG: &[u8] = b"gcal-webhook";

/// Expected decoded token length: 16 bytes user_id + 16 bytes MAC.
const TOKEN_DECODED_LEN: usize = 16 + HMAC_TAG_LEN;

/// Build the MAC input in canonical order. Never changes after
/// deployment — any reordering invalidates every issued token and
/// silently breaks every active watch channel until they expire.
///
/// Layout (byte-level, no length prefixes required since the parts
/// are fixed-size or delimited by the domain tag):
///
/// ```text
///   DOMAIN_TAG      (12 bytes, "gcal-webhook")
///   user_id         (16 bytes)
///   channel_id      (variable — UTF-8 bytes of the Google channel UUID)
/// ```
///
/// user_id is fixed-width so no length prefix is needed between the
/// prior and next field. channel_id is last, so its variable length
/// is unambiguous.
fn mac_input(user_id: Uuid, channel_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DOMAIN_TAG.len() + 16 + channel_id.len());
    buf.extend_from_slice(DOMAIN_TAG);
    buf.extend_from_slice(user_id.as_bytes());
    buf.extend_from_slice(channel_id.as_bytes());
    buf
}

/// Sign a LEGACY channel token, as channels were created before 2026-10-14.
/// Nothing mints one any more; the tests use it to prove what the window
/// admits and what it refuses.
#[cfg(test)]
pub fn sign_channel_token(user_id: Uuid, channel_id: &str, key: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(&mac_input(user_id, channel_id));
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(TOKEN_DECODED_LEN);
    out.extend_from_slice(user_id.as_bytes());
    out.extend_from_slice(&tag[..HMAC_TAG_LEN]);

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(out)
}

/// Verify an incoming LEGACY token and extract the bound `user_id`.
///
/// Returns `None` on any failure: bad base64, wrong length, or MAC
/// mismatch. Callers MUST NOT log the token — it is a bearer secret.
/// The comparison is constant-time; do not short-circuit elsewhere.
///
/// Admits nothing on its own since 2026-10-14: [`channel_token_admits`] asks
/// it only for a row with no stored hash, and only inside the window.
pub fn verify_channel_token(token: &str, channel_id: &str, key: &[u8]) -> Option<Uuid> {
    // Reject outrageously long tokens before any crypto work, bounding
    // the DoS cost of a flood of garbage webhooks. The base64 of a
    // 32-byte token is always 43 chars; 64 is a generous ceiling.
    if token.is_empty() || token.len() > 64 {
        return None;
    }

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    if decoded.len() != TOKEN_DECODED_LEN {
        return None;
    }

    let user_id_bytes: [u8; 16] = decoded[..16].try_into().ok()?;
    let user_id = Uuid::from_bytes(user_id_bytes);
    let token_mac = &decoded[16..];

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(&mac_input(user_id, channel_id));
    let expected = mac.finalize().into_bytes();

    if token_mac.ct_eq(&expected[..HMAC_TAG_LEN]).into() {
        Some(user_id)
    } else {
        None
    }
}

/// The end of the dual-verify window: 2026-12-01T00:00:00Z. Before it, a
/// channel row with no stored hash (created before 2026-10-14) is still
/// admitted by its legacy WSK token; from it on, never. Recorded in
/// `docs/engineering-log/packages/2026-10-14-inbound-credentials-hashed-and-scoped.md`.
pub const LEGACY_WSK_TOKENS_ACCEPTED_UNTIL_UNIX: i64 = 1_796_083_200;

/// Random bytes in a channel token, after the 16-byte user id.
const CHANNEL_SECRET_LEN: usize = 32;

/// Decoded length of a hashed-form token: user id + secret. Distinct from the
/// legacy [`TOKEN_DECODED_LEN`], so the two forms cannot be confused.
const HASHED_TOKEN_DECODED_LEN: usize = 16 + CHANNEL_SECRET_LEN;

/// A newly minted channel token: `token` goes to Google once, at watch
/// create, and is never stored; `token_hash` goes in the channel row.
pub struct MintedChannelToken {
    pub token: String,
    pub token_hash: String,
}

/// The stored form of a channel token: hex SHA-256 of its bytes.
#[must_use]
pub fn channel_token_hash(token: &str) -> String {
    talos_text_util::sha256_hex(token)
}

/// Mint a channel's token: the owning user id and 32 bytes from the operating
/// system's source, base64url (64 chars, within Google's 256-char limit).
#[must_use]
pub fn mint_channel_token(user_id: Uuid) -> MintedChannelToken {
    let mut raw = Vec::with_capacity(HASHED_TOKEN_DECODED_LEN);
    raw.extend_from_slice(user_id.as_bytes());
    raw.extend_from_slice(&talos_random::bytes::<CHANNEL_SECRET_LEN>());
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let token = URL_SAFE_NO_PAD.encode(raw);
    let token_hash = channel_token_hash(&token);
    MintedChannelToken { token, token_hash }
}

/// Which form a delivered token has. Neither form is authenticated by this:
/// it says which user's rows to read, and which check applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelTokenForm {
    /// Minted since 2026-10-14; checked against the row's stored hash.
    Hashed,
    /// An HMAC under the worker shared key; checked only inside the window.
    Legacy,
}

/// The user a delivered token NAMES, and its form. `None` for anything that
/// is neither form (empty, oversized, bad base64, wrong length). No key, no
/// I/O: what it returns is unauthenticated.
#[must_use]
pub fn claimed_channel_user(token: &str) -> Option<(Uuid, ChannelTokenForm)> {
    if token.is_empty() || token.len() > 64 {
        return None;
    }
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let decoded = URL_SAFE_NO_PAD.decode(token).ok()?;
    let form = match decoded.len() {
        HASHED_TOKEN_DECODED_LEN => ChannelTokenForm::Hashed,
        TOKEN_DECODED_LEN => ChannelTokenForm::Legacy,
        _ => return None,
    };
    let user_id_bytes: [u8; 16] = decoded[..16].try_into().ok()?;
    Some((Uuid::from_bytes(user_id_bytes), form))
}

/// Does `token` authenticate a push for the channel row it was routed to?
///
/// * The row has a `token_hash` (every channel created or renewed since
///   2026-10-14): only the hashed-form token whose SHA-256 that is, compared
///   in constant time. A legacy token is refused, whatever its MAC — a worker
///   holds that key (F-6).
/// * The row has none (created before): only a legacy token whose MAC verifies
///   under `legacy_key` for this channel and this user, and only before
///   [`LEGACY_WSK_TOKENS_ACCEPTED_UNTIL_UNIX`].
///
/// `user_id` is the row's owner (the user the row was read under).
#[must_use]
pub fn channel_token_admits(
    token: &str,
    channel_id: &str,
    user_id: Uuid,
    stored_hash: Option<&str>,
    legacy_key: Option<&[u8]>,
    now_unix: i64,
) -> bool {
    let Some((claimed, form)) = claimed_channel_user(token) else {
        return false;
    };
    if claimed != user_id {
        return false;
    }
    match (stored_hash, form) {
        (Some(stored), ChannelTokenForm::Hashed) => {
            !stored.is_empty()
                && stored
                    .as_bytes()
                    .ct_eq(channel_token_hash(token).as_bytes())
                    .into()
        }
        (None, ChannelTokenForm::Legacy) => {
            now_unix < LEGACY_WSK_TOKENS_ACCEPTED_UNTIL_UNIX
                && legacy_key.and_then(|key| verify_channel_token(token, channel_id, key))
                    == Some(user_id)
        }
        // A hashed row never takes a key-minted token; a legacy row never
        // takes a hashed-form token (it has nothing to compare it with).
        (Some(_), ChannelTokenForm::Legacy) | (None, ChannelTokenForm::Hashed) => false,
    }
}

/// Is this an `X-Goog-Channel-ID` Talos could have minted? Channel ids are
/// UUIDs generated at watch creation (`Uuid::new_v4().to_string()`), so the
/// legitimate population is 36 chars of `[0-9a-f-]`. The check is
/// deliberately a little wider — ≤64 chars of `[A-Za-z0-9_-]` — so it never
/// rejects a real channel and still refuses the header being used as a free
/// string: it bounds the per-channel rate-limiter key (F8) and the log line,
/// and a 64 KiB header cannot become a 64 KiB `DashMap` key.
pub fn channel_id_shape_ok(channel_id: &str) -> bool {
    !channel_id.is_empty()
        && channel_id.len() <= 64
        && channel_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod hashed_token_tests {
    use super::*;

    const CH: &str = "0f6e1d2c-3b4a-4958-8776-655443322110";
    const BEFORE_END: i64 = LEGACY_WSK_TOKENS_ACCEPTED_UNTIL_UNIX - 1;
    const AT_END: i64 = LEGACY_WSK_TOKENS_ACCEPTED_UNTIL_UNIX;

    fn worker_key() -> Vec<u8> {
        vec![0x5Au8; 32]
    }

    #[test]
    fn the_window_ends_on_2026_12_01() {
        let end = chrono::DateTime::<chrono::Utc>::from_timestamp(
            LEGACY_WSK_TOKENS_ACCEPTED_UNTIL_UNIX,
            0,
        )
        .expect("a real instant");
        assert_eq!(end.to_rfc3339(), "2026-12-01T00:00:00+00:00");
    }

    #[test]
    fn a_minted_token_names_its_user_and_its_hash_admits_it() {
        let user = Uuid::new_v4();
        let minted = mint_channel_token(user);
        assert_eq!(minted.token.len(), 64);
        assert_ne!(minted.token, minted.token_hash);
        assert_eq!(minted.token_hash, channel_token_hash(&minted.token));
        assert_eq!(
            claimed_channel_user(&minted.token),
            Some((user, ChannelTokenForm::Hashed))
        );
        assert!(channel_token_admits(
            &minted.token,
            CH,
            user,
            Some(&minted.token_hash),
            Some(&worker_key()),
            AT_END + 1_000_000,
        ));
        assert_ne!(mint_channel_token(user).token, minted.token);
    }

    /// F-6, the key scope: every worker holds the worker shared key, so a
    /// token minted under it — for the right user and the right channel —
    /// must not open a channel created since the change, inside the window
    /// or out of it.
    #[test]
    fn a_token_minted_under_the_worker_key_is_refused_by_a_hashed_channel() {
        let user = Uuid::new_v4();
        let row = mint_channel_token(user);
        let forged = sign_channel_token(user, CH, &worker_key());
        for now in [BEFORE_END, AT_END] {
            assert!(!channel_token_admits(
                &forged,
                CH,
                user,
                Some(&row.token_hash),
                Some(&worker_key()),
                now,
            ));
        }
    }

    #[test]
    fn a_hashed_channel_refuses_another_token_and_another_users() {
        let user = Uuid::new_v4();
        let row = mint_channel_token(user);
        let other = mint_channel_token(user);
        assert!(!channel_token_admits(
            &other.token,
            CH,
            user,
            Some(&row.token_hash),
            None,
            0
        ));
        // The row's own token, routed to another user's row, is refused.
        assert!(!channel_token_admits(
            &row.token,
            CH,
            Uuid::new_v4(),
            Some(&row.token_hash),
            None,
            0
        ));
        // The stored digest is not itself a credential, and an empty stored
        // hash admits nothing.
        assert!(!channel_token_admits(
            &row.token_hash,
            CH,
            user,
            Some(&row.token_hash),
            None,
            0
        ));
        assert!(!channel_token_admits(
            &row.token,
            CH,
            user,
            Some(""),
            None,
            0
        ));
        assert!(!channel_token_admits(
            "",
            CH,
            user,
            Some(&row.token_hash),
            None,
            0
        ));
    }

    /// The dual-verify window: a channel created before the change keeps
    /// verifying its legacy token until the end date, and not after it.
    #[test]
    fn a_legacy_channel_verifies_its_legacy_token_only_inside_the_window() {
        let user = Uuid::new_v4();
        let legacy = sign_channel_token(user, CH, &worker_key());
        assert!(channel_token_admits(
            &legacy,
            CH,
            user,
            None,
            Some(&worker_key()),
            BEFORE_END
        ));
        assert!(!channel_token_admits(
            &legacy,
            CH,
            user,
            None,
            Some(&worker_key()),
            AT_END
        ));
        // Without the key, or for another channel, or another user: refused.
        assert!(!channel_token_admits(
            &legacy, CH, user, None, None, BEFORE_END
        ));
        assert!(!channel_token_admits(
            &legacy,
            "another-channel",
            user,
            None,
            Some(&worker_key()),
            BEFORE_END
        ));
        assert!(!channel_token_admits(
            &legacy,
            CH,
            Uuid::new_v4(),
            None,
            Some(&worker_key()),
            BEFORE_END
        ));
        // A hashed-form token has nothing to be compared with on such a row.
        let minted = mint_channel_token(user);
        assert!(!channel_token_admits(
            &minted.token,
            CH,
            user,
            None,
            Some(&worker_key()),
            BEFORE_END
        ));
    }
}

#[cfg(test)]
mod channel_id_shape_tests {
    use super::channel_id_shape_ok;

    #[test]
    fn accepts_the_uuids_talos_mints() {
        assert!(channel_id_shape_ok(&uuid::Uuid::new_v4().to_string()));
        assert!(channel_id_shape_ok("A1b2-C3_d4"));
    }

    #[test]
    fn rejects_empty_oversized_and_free_text() {
        assert!(!channel_id_shape_ok(""));
        assert!(!channel_id_shape_ok(&"a".repeat(65)));
        assert!(channel_id_shape_ok(&"a".repeat(64)));
        assert!(!channel_id_shape_ok("has space"));
        assert!(!channel_id_shape_ok("semi;colon"));
        assert!(!channel_id_shape_ok("new\nline"));
        assert!(!channel_id_shape_ok("ünïcode"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        vec![0xA5u8; 32]
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let user = Uuid::new_v4();
        let ch = "abc-channel-123";
        let token = sign_channel_token(user, ch, &key());
        assert_eq!(verify_channel_token(&token, ch, &key()), Some(user));
    }

    #[test]
    fn token_has_expected_length() {
        let token = sign_channel_token(Uuid::nil(), "ch", &key());
        // 32 bytes base64url with no padding = 43 chars
        assert_eq!(token.len(), 43);
    }

    #[test]
    fn wrong_channel_id_rejected() {
        let user = Uuid::new_v4();
        let token = sign_channel_token(user, "chan-a", &key());
        assert!(
            verify_channel_token(&token, "chan-b", &key()).is_none(),
            "channel-id binding must reject mismatch"
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let user = Uuid::new_v4();
        let token = sign_channel_token(user, "ch", &key());
        let other_key = vec![0xFFu8; 32];
        assert!(verify_channel_token(&token, "ch", &other_key).is_none());
    }

    #[test]
    fn tampered_user_id_rejected() {
        // Flip one byte of the user_id portion; MAC should no longer match.
        let user = Uuid::new_v4();
        let token = sign_channel_token(user, "ch", &key());

        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let mut bytes = URL_SAFE_NO_PAD.decode(&token).unwrap();
        bytes[0] ^= 0xFF;
        let tampered = URL_SAFE_NO_PAD.encode(&bytes);

        assert!(verify_channel_token(&tampered, "ch", &key()).is_none());
    }

    #[test]
    fn truncated_token_rejected() {
        let token = sign_channel_token(Uuid::new_v4(), "ch", &key());
        let truncated = &token[..token.len() - 2];
        assert!(verify_channel_token(truncated, "ch", &key()).is_none());
    }

    #[test]
    fn empty_token_rejected() {
        assert!(verify_channel_token("", "ch", &key()).is_none());
    }

    #[test]
    fn oversized_token_rejected_cheaply() {
        // Anything beyond 64 chars is rejected before any base64 work
        // — a DoS lever against the decoder.
        let giant = "A".repeat(10_000);
        assert!(verify_channel_token(&giant, "ch", &key()).is_none());
    }

    #[test]
    fn bad_base64_rejected() {
        assert!(verify_channel_token("not_valid_base64!@#$", "ch", &key()).is_none());
    }

    #[test]
    fn signature_is_deterministic() {
        // Same inputs MUST always produce the same token (the webhook
        // path depends on this — we verify by re-signing effectively).
        let user = Uuid::new_v4();
        let a = sign_channel_token(user, "ch", &key());
        let b = sign_channel_token(user, "ch", &key());
        assert_eq!(a, b);
    }

    #[test]
    fn different_users_produce_different_tokens() {
        let a = sign_channel_token(Uuid::new_v4(), "ch", &key());
        let b = sign_channel_token(Uuid::new_v4(), "ch", &key());
        assert_ne!(a, b);
    }

    #[test]
    fn domain_separation_prevents_cross_context_reuse() {
        // Simulate another subsystem that might compute an HMAC over
        // "user_id || channel_id" without our domain tag. Its output
        // must NOT verify as a webhook token, because our mac_input
        // prepends DOMAIN_TAG.
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let user = Uuid::new_v4();
        let ch = "ch";

        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key()).unwrap();
        mac.update(user.as_bytes());
        mac.update(ch.as_bytes());
        let foreign_tag = mac.finalize().into_bytes();

        let mut forged = Vec::with_capacity(TOKEN_DECODED_LEN);
        forged.extend_from_slice(user.as_bytes());
        forged.extend_from_slice(&foreign_tag[..HMAC_TAG_LEN]);

        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let forged_token = URL_SAFE_NO_PAD.encode(forged);

        assert!(
            verify_channel_token(&forged_token, ch, &key()).is_none(),
            "domain tag must prevent cross-context token reuse"
        );
    }
}

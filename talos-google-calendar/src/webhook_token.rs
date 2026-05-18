//! Signed webhook token for Google Calendar push notifications.
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

/// Sign a new channel token. `channel_id` is the Google channel UUID
/// we supply to the watch-create call. `key` is the HMAC key.
pub fn sign_channel_token(user_id: Uuid, channel_id: &str, key: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&mac_input(user_id, channel_id));
    let tag = mac.finalize().into_bytes();

    let mut out = Vec::with_capacity(TOKEN_DECODED_LEN);
    out.extend_from_slice(user_id.as_bytes());
    out.extend_from_slice(&tag[..HMAC_TAG_LEN]);

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(out)
}

/// Verify an incoming token and extract the bound `user_id`.
///
/// Returns `None` on any failure: bad base64, wrong length, or MAC
/// mismatch. Callers MUST NOT log the token — it is a bearer secret.
/// The comparison is constant-time; do not short-circuit elsewhere.
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
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(&mac_input(user_id, channel_id));
    let expected = mac.finalize().into_bytes();

    if token_mac.ct_eq(&expected[..HMAC_TAG_LEN]).into() {
        Some(user_id)
    } else {
        None
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

        let mut mac = Hmac::<Sha256>::new_from_slice(&key()).unwrap();
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

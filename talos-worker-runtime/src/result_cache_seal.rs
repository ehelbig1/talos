//! The Redis tier of the module RESULT cache, sealed — ONE home (security
//! review 2026-10-14, E-4).
//!
//! `TalosRuntime` caches a module's output (when `WASM_RESULT_CACHE_TTL_SECS`
//! or the job asks for it) in-process and in Redis under
//! `wasm:result:{module_hash}:{context_hash}`. A Redis hit is returned as the
//! job's output and signed by the worker as if the module had run. Until this
//! module existed the Redis value was the output's JSON text, read back with
//! `serde_json::from_str` and nothing else: anyone who could write that Redis
//! key chose a module's output, and an output derived from a tenant's secrets
//! sat in a shared Redis in clear. The OCI module cache beside it already
//! re-verified its bytes against a digest; this one had no check at all.
//!
//! An entry is now AES-256-GCM sealed:
//!
//! * the key is per CACHE KEY — `HMAC-SHA256(seal key, label ‖ cache key)` —
//!   so the per-key message count is the number of writes of one entry (the
//!   house rule for AEAD: per-context subkeys, never one key for every row);
//! * the seal key is `HMAC-SHA256(WORKER_SHARED_KEY, label)`, so the fleet key
//!   itself never sits in the runtime and every worker of the fleet opens what
//!   another sealed;
//! * the cache key is also the AAD, and the nonce comes from `talos_random`.
//!
//! [`open`] returns `None` for anything it cannot authenticate — a flipped
//! byte, an entry moved from another cache key, an entry sealed under another
//! fleet key, and a plaintext entry in the pre-2026-10-14 format. The caller
//! treats `None` as a miss and the module runs. There is deliberately no
//! "accept the old format during the roll-out" arm: an unsealed entry is
//! exactly what an attacker writes, and a miss costs one execution.
//!
//! A runtime with no seal key (an embedded rehearsal surface, a test) does not
//! use the Redis tier at all; its in-process tier is unchanged.
//!
//! An entry also carries its own expiry, sealed with it (security review
//! 2026-10-15, E2-5): `{"v": output, "exp": unix seconds}`. [`open`] refuses an
//! expired entry whatever TTL Redis holds, so a Redis writer who cannot forge
//! an entry can no longer pin a captured, genuine one past the operator's
//! `WASM_RESULT_CACHE_TTL_SECS` by re-`SET`ting it with a longer TTL. The
//! format is `talos-rc2:`; an `rc1` entry (no expiry) is a miss.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::Value as JsonValue;
use sha2::Sha256;

/// Derives the seal key from the fleet key.
const SEAL_KEY_LABEL: &[u8] = b"talos-result-cache-seal/v1";
/// Derives one entry's AES key from the seal key and the cache key.
const ENTRY_KEY_LABEL: &[u8] = b"talos-result-cache-entry/v1";
/// Version tag in front of every sealed Redis value.
pub(crate) const SEALED_PREFIX: &str = "talos-rc2:";
const NONCE_LEN: usize = 12;

type HmacSha256 = Hmac<Sha256>;

fn hmac32(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as hmac::KeyInit>::new_from_slice(key).expect("HMAC-SHA256 accepts any key");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

/// The key the Redis tier of the result cache is sealed under.
#[derive(Clone)]
pub struct ResultCacheSealKey([u8; 32]);

impl ResultCacheSealKey {
    /// Derive from the fleet's `WORKER_SHARED_KEY` (the CURRENT signing key):
    /// every worker that holds it opens what another sealed. After a key
    /// rotation an old entry no longer opens and is a miss until it expires.
    #[must_use]
    pub fn derive(worker_shared_key: &[u8]) -> Self {
        Self(hmac32(worker_shared_key, &[SEAL_KEY_LABEL]))
    }

    fn entry_cipher(&self, cache_key: &str) -> Aes256Gcm {
        let k = hmac32(&self.0, &[ENTRY_KEY_LABEL, cache_key.as_bytes()]);
        <Aes256Gcm as aes_gcm::aead::KeyInit>::new_from_slice(&k).expect("32-byte AES-256 key")
    }
}

impl std::fmt::Debug for ResultCacheSealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResultCacheSealKey(<redacted>)")
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Seal `value` for the Redis entry `cache_key`, valid for `ttl_secs` from
/// now. `None` only if the output cannot be serialised or the cipher fails;
/// the caller then skips the write.
#[must_use]
pub fn seal(
    key: &ResultCacheSealKey,
    cache_key: &str,
    value: &JsonValue,
    ttl_secs: u64,
) -> Option<String> {
    seal_until(key, cache_key, value, now_secs().saturating_add(ttl_secs))
}

/// [`seal`] with the expiry stated (unix seconds).
fn seal_until(
    key: &ResultCacheSealKey,
    cache_key: &str,
    value: &JsonValue,
    exp: u64,
) -> Option<String> {
    let plaintext = serde_json::to_vec(&serde_json::json!({ "v": value, "exp": exp })).ok()?;
    let mut nonce = [0u8; NONCE_LEN];
    talos_random::fill(&mut nonce);
    let ciphertext = key
        .entry_cipher(cache_key)
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: cache_key.as_bytes(),
            },
        )
        .ok()?;
    let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Some(format!(
        "{SEALED_PREFIX}{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(blob)
    ))
}

/// Open the Redis value `stored` read at `cache_key`. `None` for anything that
/// does not authenticate under `key` for exactly this cache key — including an
/// unsealed (plaintext) value. Never an error the caller must handle: a `None`
/// is a cache miss and the module runs.
#[must_use]
pub fn open(key: &ResultCacheSealKey, cache_key: &str, stored: &str) -> Option<JsonValue> {
    let encoded = stored.strip_prefix(SEALED_PREFIX)?;
    let blob = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded)
        .ok()?;
    if blob.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let plaintext = key
        .entry_cipher(cache_key)
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: cache_key.as_bytes(),
            },
        )
        .ok()?;
    let mut entry: JsonValue = serde_json::from_slice(&plaintext).ok()?;
    let exp = entry.get("exp")?.as_u64()?;
    if exp < now_secs() {
        return None;
    }
    entry.get_mut("v").map(JsonValue::take)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CK: &str = "wasm:result:modhash:ctxhash";

    fn key() -> ResultCacheSealKey {
        ResultCacheSealKey::derive(&[7u8; 32])
    }

    #[test]
    fn a_sealed_entry_opens_under_the_same_key_and_cache_key() {
        let v = json!({"answer": 42, "items": ["a", "b"]});
        let sealed = seal(&key(), CK, &v, 60).expect("seals");
        assert!(sealed.starts_with(SEALED_PREFIX));
        assert_eq!(open(&key(), CK, &sealed), Some(v.clone()));
        // A second worker of the fleet derives the same seal key.
        assert_eq!(
            open(&ResultCacheSealKey::derive(&[7u8; 32]), CK, &sealed),
            Some(v)
        );
    }

    #[test]
    fn the_output_is_not_stored_in_clear() {
        let sealed = seal(&key(), CK, &json!({"token_echo": "visible-marker"}), 60).unwrap();
        assert!(!sealed.contains("visible-marker"));
        assert!(!sealed.contains("token_echo"));
    }

    /// E-4: a Redis entry with a flipped byte is ignored. Every byte of the
    /// stored value is flipped in turn — prefix, nonce, ciphertext and tag.
    #[test]
    fn an_entry_with_a_flipped_byte_is_ignored() {
        let sealed = seal(&key(), CK, &json!({"ok": true}), 60).unwrap();
        let bytes = sealed.as_bytes();
        for i in 0..bytes.len() {
            let mut b = bytes.to_vec();
            // Flip within the base64 alphabet so the decode still succeeds
            // and the AEAD tag is what refuses it.
            b[i] = match b[i] {
                b'A' => b'B',
                b'a' => b'b',
                b'0' => b'1',
                _ => b'A',
            };
            let tampered = String::from_utf8(b).unwrap();
            if tampered == sealed {
                continue;
            }
            assert_eq!(open(&key(), CK, &tampered), None, "byte {i} flipped");
        }
    }

    /// The value an attacker can write without the key — the output's JSON
    /// text, the pre-2026-10-14 format — is a miss, not an output.
    #[test]
    fn an_unsealed_entry_is_ignored() {
        let forged = json!({"forged": true}).to_string();
        assert_eq!(open(&key(), CK, &forged), None);
        assert_eq!(open(&key(), CK, &format!("{SEALED_PREFIX}{forged}")), None);
        assert_eq!(open(&key(), CK, SEALED_PREFIX), None);
        assert_eq!(open(&key(), CK, ""), None);
    }

    /// An entry copied to another cache key (another workflow's, another
    /// input's) does not open there.
    #[test]
    fn an_entry_moved_to_another_cache_key_is_ignored() {
        let sealed = seal(&key(), CK, &json!({"ok": true}), 60).unwrap();
        assert_eq!(open(&key(), "wasm:result:modhash:other", &sealed), None);
    }

    #[test]
    fn an_entry_sealed_under_another_fleet_key_is_ignored() {
        let sealed = seal(&key(), CK, &json!({"ok": true}), 60).unwrap();
        let other = ResultCacheSealKey::derive(&[8u8; 32]);
        assert_eq!(open(&other, CK, &sealed), None);
    }

    #[test]
    fn two_seals_of_one_value_differ() {
        let v = json!({"ok": true});
        assert_ne!(
            seal(&key(), CK, &v, 60),
            seal(&key(), CK, &v, 60),
            "fresh nonce"
        );
    }

    /// TEXTUAL pin: the runtime's Redis tier reads and writes ONLY through
    /// this module — no `serde_json` parse of a raw Redis value, no unsealed
    /// write.
    #[test]
    fn the_runtime_reads_and_writes_redis_only_through_the_seal() {
        let src = include_str!("runtime.rs");
        let get = &src[src.find("async fn get_cached_result(").unwrap()
            ..src.find("fn insert_to_cache(").unwrap()];
        assert!(get.contains("crate::result_cache_seal::open(seal, cache_key, &cached_str)"));
        assert!(!get.contains("serde_json::from_str"));
        let put = &src[src.find("async fn cache_result(").unwrap()..];
        let put = &put[..put.find("\n    }\n").unwrap()];
        assert!(put.contains("crate::result_cache_seal::seal(seal, cache_key, result, ttl_secs)"));
        assert!(!put.contains("serde_json::to_string"));
    }

    /// E2-5 (2026-10-15): an entry past its sealed expiry is a miss even if
    /// Redis still serves it (a re-SET with a longer TTL); one within it opens.
    #[test]
    fn an_entry_past_its_sealed_expiry_is_ignored() {
        let v = json!({"ok": true});
        let expired = seal_until(&key(), CK, &v, now_secs().saturating_sub(1)).unwrap();
        assert_eq!(open(&key(), CK, &expired), None);
        let fresh = seal_until(&key(), CK, &v, now_secs() + 60).unwrap();
        assert_eq!(open(&key(), CK, &fresh), Some(v));
    }

    #[test]
    fn the_key_is_redacted_in_debug() {
        assert_eq!(format!("{:?}", key()), "ResultCacheSealKey(<redacted>)");
    }
}

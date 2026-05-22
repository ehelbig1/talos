use dashmap::DashMap;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::time::Instant;
use zeroize::Zeroizing;

use crate::provider::{SecretProvider, SlotHandle};

/// Maximum age for a live slot before it is considered stale (rotation boundary).
///
/// If a secret is rotated after a slot is resolved, calls to `into_auth_header` or
/// `sign` on a slot older than this will return an error. This bounds the window in
/// which a compromised key can be used after emergency rotation.
///
/// Default: 300 seconds (5 minutes) — matches the job HMAC replay-prevention window.
/// Can be overridden at construction time via `TalosVaultProvider::with_max_slot_age`.
pub const DEFAULT_MAX_SLOT_AGE_SECS: u64 = 300;

/// A single materialized secret in the slot registry.
///
/// Holds the decrypted value (`Zeroizing<String>` auto-zeroes on drop) and the
/// wall-clock instant at which the slot was created. The creation time is used to
/// enforce `max_slot_age_secs`: if the slot is too old, the host rejects use and
/// logs a warning so operators know to tighten job dispatch latency or rotation windows.
struct SlotEntry {
    value: Zeroizing<String>,
    created_at: Instant,
}

impl SlotEntry {
    fn new(value: String) -> Self {
        Self {
            value: Zeroizing::new(value),
            created_at: Instant::now(),
        }
    }

    /// Returns `true` if the slot is older than `max_age_secs`.
    fn is_stale(&self, max_age_secs: u64) -> bool {
        self.created_at.elapsed().as_secs() > max_age_secs
    }
}

/// Internal Talos vault backed by a pre-fetched secret map (v1).
///
/// v1 constructor wraps a pre-fetched `HashMap<String, String>` that was
/// resolved by the controller and passed via the job message. Each value is
/// wrapped in `Zeroizing<String>` so memory is zeroed on drop.
///
/// In v2 this will gain a `db_pool + master_key` constructor for on-demand
/// DB-backed resolution, removing the need for the pre-fetch in parallel.rs.
pub struct TalosVaultProvider {
    /// Slot registry — the ONLY place decrypted values live after construction.
    /// Entries are removed by `release()`, which zeroes the value on drop.
    slots: DashMap<SlotHandle, SlotEntry>,
    /// Pre-loaded plaintext map. In v2 this will be replaced with on-demand
    /// DB resolution. Values are wrapped in Zeroizing so they zero on drop.
    resolved: HashMap<String, Zeroizing<String>>,
    /// Maximum age (in seconds) for a slot before use is rejected.
    /// Enforces a rotation boundary: after `max_slot_age_secs`, the slot is considered
    /// potentially stale and calls to `into_auth_header` / `sign` return an error.
    max_slot_age_secs: u64,
}

/// Allocate a fresh slot handle as a 63-bit CSPRNG-random value.
///
/// **Why random and not a sequential counter?** A guest WASM module
/// receives slot handles via the `secrets::get-secret` host call and
/// stores them as `u64`. With sequential allocation starting at 1, a
/// guest can trivially enumerate (`handle ± 1`) to probe slot IDs that
/// might exist. Today the WIT contract caps probing to within one
/// `Store` (each execution has its own [`TalosVaultProvider`]), so an
/// out-of-bounds probe just returns `Notfound`. The defense-in-depth
/// benefit:
///
///   1. If the per-execution scope is ever weakened (e.g. shared
///      providers across executions for caching), enumeration becomes
///      a real cross-tenant leak. Random handles fail closed in that
///      future.
///   2. A randomized handle makes the "use-after-release" pattern
///      visibly broken — a freed handle 7 is overwhelmingly unlikely
///      to be re-issued to a sibling slot.
///
/// The handle is 63 bits (top bit cleared) so it always fits in a
/// signed 64-bit integer too — some logging / metrics backends
/// downstream treat very large `u64` values as floats and lose
/// precision; clearing the high bit avoids that.
///
/// Collision probability with 63 bits over 1000 slots is on the order
/// of 1e-15 (birthday-bound) — far below any realistic concern. The
/// resolve path inserts into a [`DashMap`] which would just overwrite
/// on collision; we accept that microscopic risk for the simpler
/// code path.
fn fresh_slot_handle() -> SlotHandle {
    let mut buf = [0u8; 8];
    OsRng.fill_bytes(&mut buf);
    let v = u64::from_le_bytes(buf) & 0x7FFF_FFFF_FFFF_FFFF;
    // Make sure we never return 0 — some downstream code uses 0 as a
    // sentinel "no slot" value. Probability of hitting 0 is ~1e-19.
    SlotHandle(if v == 0 { 1 } else { v })
}

/// MCP-509: case-insensitive HTTP auth-scheme prefix detection.
///
/// Returns true if `value` starts with `scheme` (case-insensitive),
/// followed by a literal space. `scheme` is expected to be a short
/// ASCII string like `"Bearer"` or `"Basic"`. Per RFC 7235 §2.1,
/// auth-scheme tokens are case-insensitive.
fn has_auth_scheme_prefix(value: &str, scheme: &str) -> bool {
    let scheme_len = scheme.len();
    value.as_bytes().get(scheme_len).copied() == Some(b' ')
        && value
            .get(..scheme_len)
            .map(|prefix| prefix.eq_ignore_ascii_case(scheme))
            .unwrap_or(false)
}

impl TalosVaultProvider {
    /// v1 constructor: consume the pre-fetched secrets HashMap, wrapping each
    /// value in `Zeroizing<String>`. The original HashMap is dropped after
    /// construction, leaving a single copy inside this struct.
    pub fn from_resolved(secrets: HashMap<String, String>) -> Self {
        let resolved = secrets
            .into_iter()
            .map(|(k, v)| (k, Zeroizing::new(v)))
            .collect();
        Self {
            slots: DashMap::new(),
            resolved,
            max_slot_age_secs: DEFAULT_MAX_SLOT_AGE_SECS,
        }
    }

    /// Override the default slot TTL (useful for tests or long-running pipelines).
    pub fn with_max_slot_age(mut self, secs: u64) -> Self {
        self.max_slot_age_secs = secs;
        self
    }

    /// Helper to retrieve a slot and check the rotation guard boundary.
    fn get_valid_slot<'a>(
        &'a self,
        handle: SlotHandle,
        context: &str,
    ) -> anyhow::Result<dashmap::mapref::one::Ref<'a, SlotHandle, SlotEntry>> {
        let entry = self
            .slots
            .get(&handle)
            .ok_or_else(|| anyhow::anyhow!("slot {:?} not found or already released", handle))?;

        if entry.is_stale(self.max_slot_age_secs) {
            tracing::warn!(
                handle = handle.0,
                age_secs = entry.created_at.elapsed().as_secs(),
                max_age_secs = self.max_slot_age_secs,
                "{} slot rejected — age exceeds max_slot_age_secs (possible post-rotation use)",
                context
            );
            return Err(anyhow::anyhow!(
                "slot {:?} is stale (age > {}s): re-resolve after secret rotation",
                handle,
                self.max_slot_age_secs
            ));
        }

        Ok(entry)
    }
}

#[async_trait::async_trait]
impl SecretProvider for TalosVaultProvider {
    async fn resolve(&self, path: &str, _execution_id: uuid::Uuid) -> anyhow::Result<SlotHandle> {
        let plaintext = self
            .resolved
            .get(path)
            .ok_or_else(|| anyhow::anyhow!("secret path not found: {path}"))?;
        // L-13 (2026-05-22): allocate a 63-bit random handle instead
        // of a sequential counter. See `fresh_slot_handle` for the
        // defense-in-depth rationale (guest enumeration resistance).
        let handle = fresh_slot_handle();
        // Clone into a fresh SlotEntry — value is Zeroizing<String>, created_at records now.
        self.slots
            .insert(handle, SlotEntry::new((**plaintext).clone()));
        Ok(handle)
    }

    fn into_auth_header(
        &self,
        handle: SlotHandle,
        header_name: &str,
    ) -> anyhow::Result<Zeroizing<String>> {
        let entry = self.get_valid_slot(handle, "auth_header")?;
        // L-4: build the header value into a Zeroizing<String> so the
        // intermediate buffer is wiped on drop. Caller passes
        // `&Zeroizing<String>` to reqwest's HeaderValue::from_str which
        // copies into HeaderValue's own buffer; the wrapper drops + wipes
        // when the binding goes out of scope.
        let raw: &str = entry.value.as_str(); // auditable plaintext exit point
        // MCP-509: HTTP auth schemes are case-insensitive per RFC 7235
        // §2.1. Pre-fix the case-sensitive `starts_with("Bearer ")` /
        // `starts_with("Basic ")` check would prepend `Bearer ` to a
        // secret that already started with `BEARER abc` or `bearer abc`,
        // yielding a malformed `Bearer BEARER abc` value. Operators
        // commonly paste secrets in mixed case (e.g. copy from a vault
        // UI). Use case-insensitive scheme detection.
        let needs_bearer = header_name.eq_ignore_ascii_case("authorization")
            && !has_auth_scheme_prefix(raw, "Bearer")
            && !has_auth_scheme_prefix(raw, "Basic");
        let mut out = Zeroizing::new(String::with_capacity(
            raw.len() + if needs_bearer { 7 } else { 0 },
        ));
        if needs_bearer {
            out.push_str("Bearer ");
        }
        out.push_str(raw);
        Ok(out)
    }

    fn sign(&self, handle: SlotHandle, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let entry = self.get_valid_slot(handle, "hmac")?;

        // MCP-632 (2026-05-12): defense-in-depth empty-key rejection.
        // `Hmac::<Sha256>::new_from_slice` accepts ANY key length
        // including empty (HMAC is defined for any byte sequence). If a
        // resolved secret value is the empty string (legacy DB row,
        // direct SQL write, future code path that produces empty
        // ciphertext), `sign()` would produce a deterministic
        // `HMAC-SHA256("", payload)` that an attacker who knows the
        // payload could forge. The pre-fetched map should never carry
        // empty values today, but we fail-closed here regardless —
        // sibling to MCP-628 (webhook HMAC). Empty-key HMAC has no
        // legitimate use case in this codebase.
        if entry.value.is_empty() {
            tracing::warn!(
                target: "talos_secrets",
                event_kind = "vault_hmac_empty_key",
                handle = handle.0,
                "TalosVaultProvider::sign rejected: resolved secret is empty"
            );
            anyhow::bail!("cannot sign with empty secret value");
        }

        let mut mac = Hmac::<Sha256>::new_from_slice(entry.value.as_bytes())
            .map_err(|e| anyhow::anyhow!("hmac init: {e}"))?;
        mac.update(payload);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn decrypt(
        &self,
        _handle: SlotHandle,
        _ciphertext: &[u8],
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        // v1: not supported — reserved for KMS-backed providers in v2.
        anyhow::bail!("decrypt not supported by TalosVaultProvider v1")
    }

    async fn release(&self, handle: SlotHandle) -> anyhow::Result<()> {
        self.slots.remove(&handle); // SlotEntry.value (Zeroizing<String>) zeroes on drop
        Ok(())
    }

    async fn health_check(&self) -> anyhow::Result<()> {
        // v1: always healthy (in-process, no network calls)
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L-13: slot handles must be CSPRNG-random (not sequential) so a
    /// guest can't enumerate adjacent handles. We assert two
    /// properties:
    ///   1. Successive handles differ by more than 1 with overwhelming
    ///      probability — a sequential allocator would always differ
    ///      by exactly 1.
    ///   2. The high bit is cleared (fits in a signed 64-bit int).
    #[tokio::test]
    async fn slot_handles_are_random_not_sequential() {
        let mut map = HashMap::new();
        for i in 0..50 {
            map.insert(format!("path/{i}"), format!("val{i}"));
        }
        let provider = TalosVaultProvider::from_resolved(map);
        let exec_id = uuid::Uuid::new_v4();

        let mut handles = Vec::new();
        for i in 0..50 {
            let h = provider
                .resolve(&format!("path/{i}"), exec_id)
                .await
                .unwrap();
            handles.push(h.0);
        }

        // Distinctness — DashMap would overwrite on collision, but
        // 50 draws from a 63-bit space should never collide in
        // practice (birthday-bound is ~3.5 billion draws for 50%).
        let mut sorted = handles.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), handles.len(), "handles collided");

        // Adjacency check — sequential allocation would yield
        // |sorted[i+1] - sorted[i]| == 1 for every pair. Random
        // allocation produces large gaps. Assert that at least one
        // gap is much larger than 1 (CSPRNG with 50 draws from a
        // 63-bit space gives expected min-gap ≈ 2^57 / 50 ≈ 1e15).
        let any_large_gap = sorted
            .windows(2)
            .any(|w| w[1].saturating_sub(w[0]) > 1024);
        assert!(
            any_large_gap,
            "handles look sequential — slot allocator regressed?"
        );

        // High bit cleared — fits in i64 without precision loss.
        for h in &handles {
            assert!(*h < (1u64 << 63), "handle high bit set: {h}");
            assert!(*h != 0, "handle must not be 0 sentinel");
        }
    }

    #[tokio::test]
    async fn slot_lifecycle_and_release() {
        let mut map = HashMap::new();
        map.insert("test/key".to_string(), "super-secret-value".to_string());

        let provider = TalosVaultProvider::from_resolved(map);
        let exec_id = uuid::Uuid::new_v4();

        let handle = provider.resolve("test/key", exec_id).await.unwrap();
        let value = provider.into_auth_header(handle, "Authorization").unwrap();
        // Authorization header gets "Bearer " prefix for raw values
        assert_eq!(value.as_str(), "Bearer super-secret-value");

        // Release zeroes the slot
        provider.release(handle).await.unwrap();
        assert!(provider.into_auth_header(handle, "Authorization").is_err());
    }

    #[tokio::test]
    async fn bearer_prefix_not_doubled() {
        let mut map = HashMap::new();
        map.insert(
            "test/bearer".to_string(),
            "Bearer already-has-prefix".to_string(),
        );

        let provider = TalosVaultProvider::from_resolved(map);
        let handle = provider
            .resolve("test/bearer", uuid::Uuid::new_v4())
            .await
            .unwrap();

        let value = provider.into_auth_header(handle, "Authorization").unwrap();
        // Must NOT double-prefix: "Bearer Bearer already-has-prefix"
        assert_eq!(value.as_str(), "Bearer already-has-prefix");
    }

    /// MCP-509: HTTP auth-scheme case sensitivity. Pre-fix
    /// `starts_with("Bearer ")` was case-sensitive, so a secret
    /// stored as `"BEARER abc"` or `"bearer abc"` would get a
    /// second `Bearer ` prefix bolted on. RFC 7235 §2.1 makes
    /// scheme tokens case-insensitive.
    #[tokio::test]
    async fn bearer_prefix_case_insensitive() {
        for stored in [
            "Bearer abc",
            "bearer abc",
            "BEARER abc",
            "BeArEr abc",
        ] {
            let mut map = HashMap::new();
            map.insert("test/key".into(), stored.to_string());
            let provider = TalosVaultProvider::from_resolved(map);
            let handle = provider
                .resolve("test/key", uuid::Uuid::new_v4())
                .await
                .unwrap();
            let value = provider.into_auth_header(handle, "Authorization").unwrap();
            // Original case is preserved (no canonicalization); the
            // key check is that we did NOT prepend a second `Bearer `.
            assert_eq!(
                value.as_str(),
                stored,
                "stored {:?} must pass through without double-prefix",
                stored
            );
        }
    }

    #[tokio::test]
    async fn basic_prefix_case_insensitive() {
        // Same surface: `BASIC ...` and `basic ...` must NOT get a
        // `Bearer ` prefix bolted in front.
        for stored in ["Basic dXNlcjpwYXNz", "basic dXNlcjpwYXNz", "BASIC dXNlcjpwYXNz"] {
            let mut map = HashMap::new();
            map.insert("test/basic".into(), stored.to_string());
            let provider = TalosVaultProvider::from_resolved(map);
            let handle = provider
                .resolve("test/basic", uuid::Uuid::new_v4())
                .await
                .unwrap();
            let value = provider.into_auth_header(handle, "Authorization").unwrap();
            assert_eq!(value.as_str(), stored);
            assert!(
                !value.as_str().starts_with("Bearer "),
                "{} should not get Bearer prepended",
                stored
            );
        }
    }

    /// `Bearer` (six bytes) without a trailing space must NOT be
    /// detected as a scheme prefix — that's a token starting with the
    /// literal letters "Bearer", not the auth scheme. Belt-and-suspenders
    /// against future refactors.
    #[tokio::test]
    async fn bearer_only_with_trailing_space_counts() {
        let mut map = HashMap::new();
        map.insert("test/key".into(), "Bearerlooks-like-not".into());
        let provider = TalosVaultProvider::from_resolved(map);
        let handle = provider
            .resolve("test/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        let value = provider.into_auth_header(handle, "Authorization").unwrap();
        // No trailing space after "Bearer" → not a scheme prefix → gets `Bearer ` prepended.
        assert_eq!(value.as_str(), "Bearer Bearerlooks-like-not");
    }

    #[tokio::test]
    async fn unknown_path_returns_error() {
        let provider = TalosVaultProvider::from_resolved(HashMap::new());
        let result = provider
            .resolve("nonexistent/path", uuid::Uuid::new_v4())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sign_produces_hmac() {
        let mut map = HashMap::new();
        map.insert("signing/key".to_string(), "my-hmac-key".to_string());

        let provider = TalosVaultProvider::from_resolved(map);
        let handle = provider
            .resolve("signing/key", uuid::Uuid::new_v4())
            .await
            .unwrap();

        let sig = provider.sign(handle, b"payload").unwrap();
        assert!(!sig.is_empty());
    }

    /// MCP-632: defense-in-depth — `Hmac::<Sha256>::new_from_slice("")`
    /// succeeds by spec. If a resolved secret value were ever empty
    /// (legacy DB row, direct SQL write), `sign()` would produce a
    /// forgeable `HMAC-SHA256("", payload)`. Pin the empty-key
    /// rejection so a future refactor can't reintroduce the
    /// forgeable-HMAC path. Sibling to MCP-628 (webhook HMAC).
    #[tokio::test]
    async fn sign_rejects_empty_secret() {
        let mut map = HashMap::new();
        map.insert("signing/key".to_string(), String::new()); // empty!

        let provider = TalosVaultProvider::from_resolved(map);
        let handle = provider
            .resolve("signing/key", uuid::Uuid::new_v4())
            .await
            .unwrap();

        let err = provider.sign(handle, b"payload").unwrap_err();
        assert!(
            err.to_string().contains("empty secret"),
            "expected empty-secret error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn stale_slot_rejected() {
        let mut map = HashMap::new();
        map.insert("test/key".to_string(), "secret".to_string());

        // Set max age to 0 so any slot is immediately stale.
        let provider = TalosVaultProvider::from_resolved(map).with_max_slot_age(0);
        let handle = provider
            .resolve("test/key", uuid::Uuid::new_v4())
            .await
            .unwrap();

        // Ensure some time passes so the slot becomes stale
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // into_auth_header should fail on a stale slot.
        let err = provider
            .into_auth_header(handle, "Authorization")
            .unwrap_err();
        assert!(
            err.to_string().contains("stale"),
            "expected stale error, got: {}",
            err
        );
        // sign should also fail on a stale slot.
        let err = provider.sign(handle, b"payload").unwrap_err();
        assert!(
            err.to_string().contains("stale"),
            "expected stale error, got: {}",
            err
        );
    }
}

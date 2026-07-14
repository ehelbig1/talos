//! Canonical Redis cache-key + dispatch-URI format for module WASM bytes.
//!
//! Module bytes are cached in Redis under a **user-scoped** key so one
//! tenant can never read another's compiled artifact out of the cache
//! (finding L-27). Three crates have to agree on the exact byte-form:
//!
//! * `talos-registry` writes the bytes with [`scoped_wasm_cache_key`]
//!   during dispatch-prep pre-warm, under the *executing* user's id.
//! * `talos-workflow-engine` emits [`scoped_wasm_redis_uri`] as the
//!   `DispatchJob.module_uri` for a redis-routed module (no `oci_url`),
//!   under the SAME executing user's id.
//! * the worker strips the `redis:` prefix and `GET`s the remainder —
//!   which is exactly [`scoped_wasm_cache_key`].
//!
//! Keeping the format in this one crate — the only crate both the
//! registry and the engine already depend on — makes the key and the URI
//! impossible to drift apart. The `redis_uri_is_key_with_redis_prefix`
//! test pins the strip-relationship the worker relies on.

use uuid::Uuid;

/// Redis key holding a module's WASM bytes, scoped to the executing user.
///
/// Shape: `wasm:{user_id}:{module_id}`. Written by the registry's
/// pre-warm/read paths; never a bare `wasm:{module_id}` (the legacy
/// non-scoped shadow key was cross-tenant readable — L-27).
pub fn scoped_wasm_cache_key(user_id: Uuid, module_id: Uuid) -> String {
    format!("wasm:{user_id}:{module_id}")
}

/// Dispatch `module_uri` the engine emits for a redis-routed module (one
/// with no `oci_url` whose bytes aren't embedded inline). The worker
/// strips the leading `redis:` and `GET`s the remainder, which is exactly
/// [`scoped_wasm_cache_key`] — so the engine's emit and the registry's
/// pre-warm resolve the same key.
pub fn scoped_wasm_redis_uri(user_id: Uuid, module_id: Uuid) -> String {
    format!("redis:{}", scoped_wasm_cache_key(user_id, module_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_user_scoped() {
        let user = Uuid::parse_str("00000000-0000-0000-0000-000000000009").unwrap();
        let module = Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap();
        assert_eq!(
            scoped_wasm_cache_key(user, module),
            "wasm:00000000-0000-0000-0000-000000000009:00000000-0000-0000-0000-000000000003"
        );
    }

    #[test]
    fn redis_uri_is_key_with_redis_prefix() {
        // The worker's fetch path does `module_uri.strip_prefix("redis:")`
        // then `GET`s the result. Pin that identity so the emit format and
        // the cache-key format can never drift.
        let user = Uuid::new_v4();
        let module = Uuid::new_v4();
        let uri = scoped_wasm_redis_uri(user, module);
        assert_eq!(
            uri.strip_prefix("redis:"),
            Some(scoped_wasm_cache_key(user, module).as_str())
        );
    }
}

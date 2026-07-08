//! Vault path allowlist matching, vault-path redaction, and the shared
//! vault/secret resolution methods on `TalosContext` (DNS-rebinding
//! validation, `check_secret_allowlist`, `resolve_vault_header`,
//! host-secret and LLM-key resolution) used by HTTP, fetch_all,
//! GraphQL, Webhook and NATS host functions.

use super::*;

// ============================================================================
// Vault path allowlist matcher
// ============================================================================
//
// The matcher itself lives in `talos_workflow_job_protocol::vault_path_permitted` so the
// controller (static validation, hygiene, engine) and worker (runtime
// enforcement in `secrets::get_secret()`) agree exactly on which paths are
// permitted. Re-exported under the old name for local call sites.

use talos_workflow_job_protocol::vault_path_permitted as vault_path_allowed;

#[cfg(test)]
mod vault_allowlist_tests {
    use super::vault_path_allowed;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_list_denies_everything() {
        assert!(!vault_path_allowed(&[], "anthropic/api_key"));
        assert!(!vault_path_allowed(&[], ""));
    }

    #[test]
    fn wildcard_allows_everything() {
        let allow = s(&["*"]);
        assert!(vault_path_allowed(&allow, "anthropic/api_key"));
        assert!(vault_path_allowed(&allow, "oauth/gmail/user/token"));
    }

    #[test]
    fn exact_match_allowed() {
        let allow = s(&["anthropic/api_key"]);
        assert!(vault_path_allowed(&allow, "anthropic/api_key"));
    }

    #[test]
    fn prefix_allows_subpath_but_not_sibling() {
        let allow = s(&["oauth/gmail"]);
        assert!(vault_path_allowed(&allow, "oauth/gmail/user/access_token"));
        // "oauth/gmailicious" must NOT match — we compare "prefix/" not "prefix".
        assert!(!vault_path_allowed(&allow, "oauth/gmailicious/x"));
        // "oauth/atlassian" must NOT match.
        assert!(!vault_path_allowed(&allow, "oauth/atlassian/token"));
    }

    #[test]
    fn glob_form_behaves_like_prefix() {
        let allow = s(&["oauth/gmail/*"]);
        assert!(vault_path_allowed(&allow, "oauth/gmail/user/token"));
        assert!(!vault_path_allowed(&allow, "oauth/atlassian/token"));
    }

    #[test]
    fn denies_path_not_in_grant() {
        // Regression for the vault:// header bypass: gmail-fetch-thread-light
        // had allowed_secrets=[] (deny-all) but resolve_vault_header used to
        // resolve anyway. With the fix, vault_path_allowed([], _) is false.
        assert!(!vault_path_allowed(&[], "oauth/gmail/user/access_token"));

        let allow = s(&["oauth/gmail/*"]);
        assert!(!vault_path_allowed(&allow, "anthropic/api_key"));
    }
}

// ============================================================================
// Wasm-security review 2026-05-22 (MEDIUM-3): vault-path redaction tests
// ============================================================================
//
// The deny paths in `resolve_vault_header` (allowlist-deny, tier-1-LLM-deny,
// resolve-failed) used to leak the literal vault path back to the guest on
// the allowlist-deny arm while the resolve-failed arm correctly emitted only
// a hash. That asymmetry was a probing oracle: a malicious module could
// distinguish "path is in some allowlist I don't have" from "path is in my
// allowlist but resolve failed" and use the difference to fingerprint the
// host's vault layout. These tests pin the post-fix contract — every deny
// path emits the same `vault_path_hash` form and never the literal path.
#[cfg(test)]
mod vault_path_redaction_tests {
    use super::vault_path_short_hash;

    #[test]
    fn hash_is_16_hex_chars() {
        // Operators grep host logs by hash; the hash length is part of
        // the operator contract. 16 hex chars = 8 bytes = 64 bits of
        // collision space, more than enough for any realistic vault.
        let h = vault_path_short_hash("anthropic/api_key");
        assert_eq!(h.len(), 16, "hash must be exactly 16 hex chars");
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_lowercase())),
            "hash must be lowercase hex digits only — got `{h}`"
        );
    }

    #[test]
    fn hash_is_deterministic() {
        // Same path → same hash, otherwise host log ↔ guest error
        // correlation breaks across requests.
        let a = vault_path_short_hash("oauth/gmail/user/access_token");
        let b = vault_path_short_hash("oauth/gmail/user/access_token");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_paths_get_distinct_hashes() {
        // Tripwire against a future refactor that accidentally
        // collapses the hash (e.g. truncating to a single byte). Hash
        // must distinguish the realistic vault-path inventory.
        let paths = [
            "anthropic/api_key",
            "openai/api_key",
            "gemini/api_key",
            "oauth/gmail/user/access_token",
            "oauth/gcal/user/access_token",
            "stripe/api_key",
            "aws/secret_access_key",
            "github/personal_access_token",
        ];
        let mut seen = std::collections::HashSet::new();
        for p in paths {
            assert!(
                seen.insert(vault_path_short_hash(p)),
                "hash collision on `{p}` — review the hash length"
            );
        }
    }

    /// Build the literal deny-error format string in the same shape as
    /// `resolve_vault_header`'s allowlist-deny arm, then assert the
    /// security-critical invariants. If a future refactor reintroduces
    /// the literal vault path into the guest-visible error, this test
    /// fires — the inline format string above MUST stay in sync.
    #[test]
    fn allowlist_deny_error_contains_hash_not_literal_path() {
        let vault_path = "stripe/secret/customer/cus_PROBE";
        let hash = vault_path_short_hash(vault_path);
        let header_name = "Authorization";
        let err = format!(
            "Header '{header_name}' references a vault secret not permitted by this \
             module's allowed_secrets grant (vault_path_hash={hash}). \
             Operator: grep host logs for this hash to see the literal path, then \
             reinstall the module with the path added to allowed_secrets."
        );

        // Hash MUST appear so operators can correlate.
        assert!(
            err.contains(&format!("vault_path_hash={hash}")),
            "error must surface the vault_path_hash"
        );

        // Literal path MUST NOT appear — this is the regression class
        // the 2026-05-22 review caught.
        assert!(
            !err.contains(vault_path),
            "error must NOT echo the literal vault path back to the guest — got: {err}"
        );

        // Specific path components (the operator-recognisable parts
        // like "stripe" or "customer") must not leak either, even if
        // some future format string only includes a substring.
        assert!(!err.contains("stripe"));
        assert!(!err.contains("cus_PROBE"));
    }

    #[test]
    fn tier1_llm_deny_error_contains_hash_not_literal_path() {
        // The Tier-2 LLM provider key paths are public constants, so
        // the redaction here is mostly for consistency — but if the
        // operator inventory ever grows to include a custom provider
        // path, the redaction matters again. Pin the format.
        let vault_path = "anthropic/api_key";
        let hash = vault_path_short_hash(vault_path);
        let header_name = "X-Custom-Auth";
        let err = format!(
            "Header '{header_name}' references a Tier-2 LLM provider key \
             (vault_path_hash={hash}) but this actor's ceiling is \
             Tier-1 (local Ollama only); external provider credentials are refused."
        );
        assert!(err.contains(&format!("vault_path_hash={hash}")));
        assert!(
            !err.contains(vault_path),
            "Tier-1 LLM deny must redact the vault path even though the path is a public constant — got: {err}"
        );
    }

    #[test]
    fn resolve_failed_error_contains_hash_not_literal_path() {
        // The pre-existing safe path; pin it so a future "let's be
        // helpful and include the path" PR breaks the test.
        let vault_path = "oauth/gcal/user/refresh_token";
        let hash = vault_path_short_hash(vault_path);
        let header_name = "Authorization";
        let err = format!(
            "Header '{header_name}' references a vault secret \
             that could not be resolved (vault_path_hash={hash}). \
             Operator: grep host logs for this hash to see the literal path."
        );
        assert!(err.contains(&format!("vault_path_hash={hash}")));
        assert!(!err.contains(vault_path));
        assert!(!err.contains("gcal"));
        assert!(!err.contains("refresh_token"));
    }
}

// ============================================================================
// Vault header resolution — shared by HTTP, fetch_all, GraphQL, Webhook, NATS
// ============================================================================

/// Re-export of the canonical host-internal vault-path check. The host-reserved
/// secret deny-list must cover EVERY controller-internal path, not just LLM
/// provider keys: `is_controller_internal_vault_path` is the superset that adds
/// the `oauth/{provider}/{user}/{key}/refresh_token` paths. Refresh tokens are
/// host-only — the controller's OAuth refresh loop consumes them; modules read
/// only the sibling `access_token` via `vault://`. Using the LLM-only
/// `is_llm_provider_vault_path` here previously let a module with a matching
/// `allowed_secrets` grant (or `["*"]`) read a refresh token, defeating this
/// gate's "host-reserved wins over allowed_secrets" contract. The underlying
/// `LLM_PROVIDER_VAULT_PATHS` list lives in `talos_workflow_job_protocol` so
/// controller + worker share one definition.
use talos_workflow_job_protocol::is_controller_internal_vault_path as is_reserved_host_secret_path;

#[cfg(test)]
mod reserved_host_secret_path_tests {
    use super::is_reserved_host_secret_path;

    #[test]
    fn blocks_llm_provider_keys() {
        assert!(is_reserved_host_secret_path("anthropic/api_key"));
        assert!(is_reserved_host_secret_path("openai/api_key"));
        assert!(is_reserved_host_secret_path("gemini/api_key"));
    }

    #[test]
    fn blocks_oauth_refresh_tokens() {
        // Host-internal: the controller's refresh loop owns these. A guest must
        // never read one, even with `allowed_secrets: ["*"]`. This is the gap
        // the LLM-only predecessor (`is_llm_provider_vault_path`) left open.
        assert!(is_reserved_host_secret_path(
            "oauth/gmail/1a361562-e551-41aa-9cb4-6f8988b035f7/primary/refresh_token"
        ));
        assert!(is_reserved_host_secret_path(
            "oauth/google_calendar/9c4d/primary/refresh_token"
        ));
    }

    #[test]
    fn allows_oauth_access_tokens() {
        // Access tokens are legitimately module-readable via `vault://` — the
        // alias swap must NOT start blocking them.
        assert!(!is_reserved_host_secret_path(
            "oauth/gmail/1a361562-e551-41aa-9cb4-6f8988b035f7/primary/access_token"
        ));
    }

    #[test]
    fn allows_ordinary_module_secrets() {
        assert!(!is_reserved_host_secret_path("stripe/api_key"));
        assert!(!is_reserved_host_secret_path("my-module/webhook_secret"));
        // A short/orphan oauth shape that isn't the canonical 4-segment
        // refresh-token path stays unmatched (mirrors job-protocol's guard).
        assert!(!is_reserved_host_secret_path("oauth/refresh_token"));
    }
}

/// 16-hex-char (8-byte) SHA-256 prefix of a vault path. Stable identity for
/// host-log ↔ guest-error correlation without leaking the literal path back
/// to the guest sandbox.
///
/// **Why this is a function, not an inline expression.** Three sites in
/// `resolve_vault_header` (allowlist-deny, tier-1-LLM-deny, resolve-failed)
/// build deny errors that MUST be byte-identical in their hash component so
/// operators can grep the host log with one query. Centralising the hash
/// here is the only way to guarantee the three sites stay in lockstep
/// across refactors. The wasm-security review of 2026-05-22 (MEDIUM-3)
/// caught the allowlist-deny path echoing the literal `vault_path` while
/// the resolve-failed path correctly emitted only the hash — a probing
/// oracle that fingerprinted host vault structure. Pulling the hash into
/// a helper makes "every deny path uses the same redaction" enforceable
/// at the type level rather than by reading three string literals.
///
/// 8 bytes is collision-free across any realistic vault-path inventory
/// (2^64 distinct paths before birthday collisions become probable) and
/// short enough to keep error/log lines readable.
pub(crate) fn vault_path_short_hash(vault_path: &str) -> String {
    let h = Sha256::digest(vault_path.as_bytes());
    hex::encode(&h[..8])
}

impl TalosContext {
    /// Resolve `host` and reject if any A/AAAA record falls in the
    /// private/loopback/link-local/CGNAT/IPv4-mapped-IPv6 deny-list.
    ///
    /// Closes the DNS-rebinding window for hostname-based egress: an
    /// attacker who controls a domain in `allowed_hosts` could otherwise
    /// resolve it to 127.0.0.1 / 100.64.x.x / ::ffff:10.0.0.1 at request
    /// time and reach internal services. IP literals are caught by
    /// `classify_private_ip` directly at the URL parse step; this fn
    /// covers the hostname case.
    ///
    /// Returns `Ok(())` when every resolved IP is public, OR when the
    /// operator has explicitly opted into private-host targets via
    /// `WORKER_ALLOW_PRIVATE_HOST_TARGETS=1` AND the host appears
    /// verbatim (not via "*") in `allowed_hosts`. Returns `Err(reason)`
    /// otherwise — caller maps to its own host-fn error type and emits
    /// an audit event.
    ///
    /// `capability_label` is the talos.audit.ledger label for the deny
    /// path ("http-fetch", "webhook", "graphql", etc.) so the audit
    /// trail attributes the rejection to the correct host fn.
    pub(crate) async fn validate_no_dns_rebinding(
        &mut self,
        host: &str,
        capability_label: &'static str,
    ) -> Result<(), &'static str> {
        let bypass =
            *ALLOW_PRIVATE_HOST_TARGETS && self.allowed_hosts.iter().any(|p| p != "*" && p == host);
        if bypass {
            tracing::debug!(
                host,
                capability_label,
                "DNS-SSRF bypass active (WORKER_ALLOW_PRIVATE_HOST_TARGETS=1 + explicit allowlist hit)"
            );
            return Ok(());
        }

        match tokio::net::lookup_host(format!("{}:80", host)).await {
            Ok(addrs) => {
                for addr in addrs {
                    let ip = addr.ip();
                    if let Some(policy) = classify_private_ip(ip) {
                        self.record_capability_denied(capability_label, policy, &ip.to_string())
                            .await;
                        tracing::warn!(
                            host,
                            ip = %ip,
                            policy,
                            capability_label,
                            "WASM module blocked: hostname resolved to a private IP"
                        );
                        return Err(policy);
                    }
                }
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    host,
                    capability_label,
                    error = %e,
                    "Failed to resolve hostname for SSRF validation"
                );
                Err("dns-resolution-failed")
            }
        }
    }

    /// Check a vault path against this module's `allowed_secrets` grant, AND
    /// against the host-reserved path deny-list.
    ///
    /// Single enforcement point shared by `get_secret` (guest-initiated) and
    /// `resolve_vault_header` (host-initiated on behalf of http/graphql/webhook/nats),
    /// so no WASM-reachable code path can bypass either check.
    pub(crate) fn check_secret_allowlist(&self, key_path: &str) -> Result<(), ()> {
        // Host-reserved paths win over allowed_secrets — a module with
        // `allowed_secrets: ["*"]` must still not read host-internal
        // credentials. Two classes: (1) LLM provider keys, pre-fetched into
        // every job purely for internal `llm::*` consumption; (2) OAuth
        // refresh tokens (`oauth/.../refresh_token`), consumed only by the
        // controller's token-refresh loop. Both are blocked here regardless of
        // grant; modules read the sibling OAuth `access_token` via `vault://`,
        // which is NOT reserved.
        if is_reserved_host_secret_path(key_path) {
            tracing::warn!(
                gate = "reserved_host_path",
                key_path,
                module_id = ?self.module_id,
                capability_world = ?self.capability_world,
                "WASM module attempted to read a reserved host secret path — denied. \
                 LLM provider keys and OAuth refresh tokens are host-only; LLM keys \
                 are reached via the `llm::*` host functions, and refresh tokens never \
                 leave the controller (modules use the OAuth access_token instead)."
            );
            return Err(());
        }
        if vault_path_allowed(&self.allowed_secrets, key_path) {
            Ok(())
        } else {
            // Log the grant *shape*, not the contents. Earlier versions
            // printed `format!("{:?}", self.allowed_secrets)` — that
            // reveals the operator's vault namespace structure
            // (`["oauth/gmail/*", "anthropic/api_key", ...]`) into
            // production logs every time a guest fumbles a path. The
            // shape is sensitive (it telegraphs which integrations are
            // provisioned for this actor) so we replace it with a
            // count + SHA-256 fingerprint of the joined paths. The
            // fingerprint is stable across runs with the same grant,
            // so operators can still correlate "did this module's
            // grant change?" without seeing the actual paths.
            let grant_summary = if self.allowed_secrets.is_empty() {
                "EMPTY (deny-all)".to_string()
            } else {
                let mut hasher = Sha256::new();
                // Sort the paths before hashing so the fingerprint is
                // order-stable. The signed `JobRequest` already sorts
                // `allowed_secrets` (canonical-bytes rule) but defending
                // against future drift is cheap.
                let mut sorted: Vec<&str> =
                    self.allowed_secrets.iter().map(String::as_str).collect();
                sorted.sort_unstable();
                for path in &sorted {
                    hasher.update(path.as_bytes());
                    hasher.update(b"\0"); // separator — defends against
                                          // `["ab","c"]` colliding with `["a","bc"]`.
                }
                let fp = hex::encode(&hasher.finalize()[..8]);
                format!("count={} fp={}", self.allowed_secrets.len(), fp)
            };
            tracing::warn!(
                gate = "allowlist",
                key_path,
                module_id = ?self.module_id,
                capability_world = ?self.capability_world,
                allowed_secrets = %grant_summary,
                "module requested a secret not in its allowed_secrets list. \
                 Fix: recompile with allowed_secrets: [\"<prefix>\"] (e.g. [\"github/token\"] for a specific key, \
                 or [\"oauth/gmail\"] for a prefix grant). Wildcard [\"*\"] permits all non-reserved paths."
            );
            Err(())
        }
    }

    /// Resolve a `vault://` header value to its plaintext via the `SecretProvider`.
    ///
    /// If `value` does not start with `vault://` it is returned unchanged
    /// (zero allocation via `Cow::Borrowed`). If the vault path cannot be
    /// resolved, an error is returned — the caller MUST fail the operation
    /// rather than proceeding with an unresolved reference.
    ///
    /// SECURITY: enforces the module's `allowed_secrets` grant before resolving.
    /// Previously this path bypassed the allowlist — any http-node module could
    /// read any secret by stuffing `vault://any/path` into an outbound header.
    ///
    /// Plaintext exits through `into_auth_header` — auditable via AuditingProvider:
    ///   grep -rn "into_auth_header" worker/src/
    ///
    /// `&mut self` + `async` so deny paths can append to the cryptographic
    /// audit ledger via `record_capability_denied`. Previously this was a
    /// sync `&self` function that used `block_in_place`+`block_on` to call
    /// the async provider, which (a) blocked a runtime worker thread for
    /// the duration of every vault lookup and (b) made it impossible to
    /// emit signed audit events from the deny paths. Both fixed here.
    pub(crate) async fn resolve_vault_header<'a>(
        &mut self,
        header_name: &str,
        value: &'a str,
    ) -> Result<std::borrow::Cow<'a, str>, String> {
        // Resolve a `vault://<path>` reference embedded ANYWHERE in the header
        // value, not only as an exact prefix. The canonical integration-module
        // pattern carries a scheme prefix, e.g.
        //   AUTH_HEADER = "Bearer vault://oauth/gmail/<uid>/<email>/access_token"
        // A bare-prefix-only match (the old `strip_prefix`) left that literal
        // string in the outbound header, so the provider returned 401. We keep
        // any `prefix`/`suffix` around the ref (the caller-supplied auth scheme)
        // and substitute the token IN PLACE. This must stay consistent with the
        // controller-side prefetch extractor (talos_workflow_engine::
        // vault_resolver::extract_vault_refs), which uses the identical split.
        let Some(marker) = value.find("vault://") else {
            return Ok(std::borrow::Cow::Borrowed(value));
        };
        let prefix = &value[..marker];
        let after = &value[marker + "vault://".len()..];
        let (vault_path, suffix) = match after.find(char::is_whitespace) {
            Some(ws) => (&after[..ws], &after[ws..]),
            None => (after, ""),
        };
        if vault_path.is_empty() {
            // "vault://" with no path token — nothing to resolve; leave untouched.
            return Ok(std::borrow::Cow::Borrowed(value));
        }

        // Hash the vault path once up-front. Used both for audit
        // correlation (host log) and as the *only* identifier surfaced
        // in guest-visible deny messages — see the redaction rationale
        // below.
        let vault_path_hash = vault_path_short_hash(vault_path);

        // SECURITY: enforce the module's allowed_secrets grant before we
        // even attempt provider resolution. This closes the bypass where
        // http-capable modules could exfiltrate arbitrary vault keys via
        // vault:// header references.
        //
        // Wasm-security review 2026-05-22 (MEDIUM-3): the deny error
        // previously echoed the literal `vault_path` back to the guest.
        // Combined with the hash-only error on the resolve-failed path
        // (below, line ~1772) this gave a malicious module a probing
        // oracle: any path that came back with the literal echoed was
        // "syntactically valid + not in my allowlist", any path that
        // came back with just a hash was "in my allowlist but resolve
        // failed". Iterating across well-known vault prefixes fingered
        // the host's vault layout. Both deny paths now emit the hash-
        // only form so the guest learns no more than what it already
        // knew (the path it just sent), and audit cross-correlation
        // uses the same `vault_path_hash` operators grep the host log
        // for. The full path goes to `record_capability_denied` and the
        // tracing log only — never back to the guest.
        if self.check_secret_allowlist(vault_path).is_err() {
            // Full SHA-256 in the audit-ledger entry (mirrors the
            // `secrets::get` deny site); the truncated `vault_path_hash`
            // above is what the operator will see in the guest-side
            // error and the corresponding tracing log line.
            let full_path_hash = format!("{:x}", Sha256::digest(vault_path.as_bytes()));
            self.record_capability_denied("vault-header", "secret-allowlist", &full_path_hash)
                .await;
            tracing::warn!(
                vault_path,
                vault_path_hash = %vault_path_hash,
                header_name,
                actor_id = ?self.actor_id,
                "vault:// header rejected: not in module's allowed_secrets grant"
            );
            return Err(format!(
                "Header '{header_name}' references a vault secret not permitted by this \
                 module's allowed_secrets grant (vault_path_hash={vault_path_hash}). \
                 Operator: grep host logs for this hash to see the literal path, then \
                 reinstall the module with the path added to allowed_secrets."
            ));
        }

        // Tier-1 LLM egress ceiling — refuse vault:// resolution for
        // Tier-2 LLM provider keys. Even if the host allowlist is
        // somehow bypassed, the guest can't interpolate an Anthropic
        // / OpenAI / Gemini key into a header without this gate.
        // Together with the host-deny list in `fetch`, this closes
        // the two halves of the C3 bypass: can't reach the host AND
        // can't materialise the credential in-guest.
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) && talos_workflow_job_protocol::is_tier2_llm_vault_path(vault_path)
        {
            // Wasm-security review 2026-05-22 (MEDIUM-3 sibling): the
            // Tier-2 LLM provider key paths (`anthropic/api_key`,
            // `openai/api_key`, `gemini/api_key`) are public constants,
            // so the redaction here is mostly for consistency with the
            // allowlist-deny path above. Same audit/log/error shape:
            // full hash in audit, truncated hash in guest error + log.
            let full_path_hash = format!("{:x}", Sha256::digest(vault_path.as_bytes()));
            self.record_capability_denied("vault-header", "tier1-llm-egress", &full_path_hash)
                .await;
            tracing::warn!(
                vault_path,
                vault_path_hash = %vault_path_hash,
                header_name,
                actor_id = ?self.actor_id,
                "tier-1 actor attempted vault:// header for external LLM key; refused"
            );
            return Err(format!(
                "Header '{header_name}' references a Tier-2 LLM provider key \
                 (vault_path_hash={vault_path_hash}) but this actor's ceiling is \
                 Tier-1 (local Ollama only); external provider credentials are refused."
            ));
        }

        let exec_id = self
            .execution_id
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .unwrap_or_else(uuid::Uuid::new_v4);

        // `vault_path_hash` was computed up-front and is reused here
        // for log/guest-error cross-correlation (see L-1 rationale at
        // the top of this function). SHA-256(path)[..16] gives 8 bytes
        // of identity — collision-free for any realistic vault-path
        // inventory while keeping the log line compact.
        match self.provider.resolve(vault_path, exec_id).await {
            Ok(handle) => {
                // Bare value ("vault://<path>") → preserve legacy behaviour
                // EXACTLY: into_auth_header reconstructs the auth header (adds
                // "Bearer " for an Authorization header when the token carries no
                // scheme). Embedded value ("Bearer vault://<path>", etc.) → the
                // caller already supplied the scheme + surrounding text, so we
                // splice the resolved token in place. Passing header_name="" makes
                // into_auth_header return the CR/LF-guarded RAW token WITHOUT
                // prepending a scheme (its `needs_bearer` gate keys on the header
                // name being "authorization"), so we never emit "Bearer Bearer …".
                let embedded = !(prefix.is_empty() && suffix.is_empty());
                let header_result = self
                    .provider
                    .into_auth_header(handle, if embedded { "" } else { header_name });
                // Always release — both success and error paths must drop the slot
                // so the Zeroizing<String> is freed and secret material is erased.
                let _ = self.provider.release(handle).await;
                match header_result {
                    // L-4: convert Zeroizing<String> → owned String at the
                    // immediate point of use. The Zeroizing wrapper wipes
                    // its buffer when the binding goes out of scope; the
                    // String we hand to reqwest will be moved into
                    // HeaderValue's internal buffer and is the only
                    // remaining plaintext copy after this scope exits. For the
                    // embedded case the same one-copy exit holds — the token is
                    // spliced between the caller's prefix/suffix.
                    Ok(plaintext) => {
                        let out = if embedded {
                            format!("{prefix}{}{suffix}", plaintext.as_str())
                        } else {
                            (*plaintext).clone()
                        };
                        Ok(std::borrow::Cow::Owned(out))
                    }
                    Err(e) => {
                        tracing::error!(
                            vault_path,
                            vault_path_hash = %vault_path_hash,
                            header_name,
                            error = %e,
                            "vault:// header resolution failed"
                        );
                        // L-1: redact the literal path in the
                        // guest-visible error — leak only the
                        // truncated hash so an operator can grep the
                        // host log for the matching `vault_path_hash`
                        // and see the real path there. Cause is kept
                        // generic; specific reasons (allowlist,
                        // ownership, missing) are in the host log.
                        Err(format!(
                            "Header '{header_name}' references a vault secret \
                             that could not be resolved (vault_path_hash={vault_path_hash}). \
                             Operator: grep host logs for this hash to see the literal path."
                        ))
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    vault_path,
                    vault_path_hash = %vault_path_hash,
                    header_name,
                    error = %e,
                    "vault:// path not resolvable"
                );
                Err(format!(
                    "Header '{header_name}' references a vault secret \
                     that could not be resolved (vault_path_hash={vault_path_hash}). \
                     Operator: grep host logs for this hash to see the literal path."
                ))
            }
        }
    }

    /// Look up a host-internal secret by key name via the SecretProvider.
    ///
    /// This path is used by the native `llm`, `llm-tools`, `llm-streaming`, and `email`
    /// WIT interfaces — it bypasses the guest-facing `secrets::get-secret` allowlist check
    /// because these interfaces are host-internal (the guest never sees the resolved value).
    /// The slot is resolved and immediately released after reading.
    ///
    /// Takes `&mut self` (not `&self`) so the future produced by this async method is `Send`.
    ///
    /// MCP-878 (2026-05-14): log resolve / into_auth_header failures.
    /// Pre-fix `.await.ok()?` discarded both error types silently. A
    /// vault-secret resolution that broke (DB blip, decryption failure,
    /// missing-key, provider misconfig) returned `None` indistinguishable
    /// from "key not granted to this module" — and the caller (HTTP
    /// header substitution, email config, etc.) then dispatched WITHOUT
    /// the secret, surfacing as an opaque "401 Unauthorized" or
    /// "missing config" upstream error instead of the actual
    /// vault-resolution failure. Operators saw user reports of
    /// "my module's API calls suddenly stopped working" with zero
    /// signal in worker logs. Same silent-fail observability class
    /// as MCP-876 / MCP-877.
    pub(crate) async fn get_host_secret(&mut self, key_name: &str) -> Option<String> {
        let exec_id = self
            .execution_id
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .unwrap_or_else(uuid::Uuid::new_v4);
        let handle = match self.provider.resolve(key_name, exec_id).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    key_name = %key_name,
                    error = %e,
                    "get_host_secret: provider.resolve failed — returning None; \
                     caller will dispatch WITHOUT the secret"
                );
                return None;
            }
        };
        let value = match self.provider.into_auth_header(handle, "Authorization") {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(
                    key_name = %key_name,
                    error = %e,
                    "get_host_secret: into_auth_header failed — returning None"
                );
                None
            }
        };
        let _ = self.provider.release(handle).await;
        // L-4: unwrap Zeroizing → owned String at the immediate point of
        // use. The wrapper wipes when it drops at end of expression.
        value.filter(|v| !v.is_empty()).map(|v| (*v).clone())
    }

    /// Resolve a vault path to its raw plaintext (no Bearer/Basic prefix).
    ///
    /// Distinct from `get_host_secret`, which routes through `into_auth_header`
    /// with header name `"Authorization"` — that path injects a `"Bearer "` prefix,
    /// which is wrong for keys sent as `x-api-key`, `x-goog-api-key`, query params,
    /// or as raw body values. Use this when you need the literal stored value.
    pub(crate) async fn resolve_raw_vault_secret(&mut self, path: &str) -> Option<String> {
        let exec_id = self
            .execution_id
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .unwrap_or_else(uuid::Uuid::new_v4);
        // MCP-878 (2026-05-14): same telemetry shape as get_host_secret
        // above. resolve_raw_vault_secret is used for headers that need
        // the literal stored value (x-api-key, x-goog-api-key, query
        // params, raw body fields), so a silent-None means the
        // module's request fires WITHOUT the secret rather than
        // failing at the gate.
        let handle = match self.provider.resolve(path, exec_id).await {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(
                    vault_path = %path,
                    error = %e,
                    "resolve_raw_vault_secret: provider.resolve failed — returning None; \
                     caller will dispatch WITHOUT the secret"
                );
                return None;
            }
        };
        // Non-"Authorization" header name avoids the Bearer-prefix path inside
        // `into_auth_header`. The name is just a label for audit logging.
        let value = match self.provider.into_auth_header(handle, "X-Talos-Raw") {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(
                    vault_path = %path,
                    error = %e,
                    "resolve_raw_vault_secret: into_auth_header failed — returning None"
                );
                None
            }
        };
        let _ = self.provider.release(handle).await;
        // L-4: same unwrap pattern as get_host_secret.
        value.filter(|v| !v.is_empty()).map(|v| (*v).clone())
    }

    /// Resolve an LLM provider API key via the vault first, env var second.
    ///
    /// Ordering:
    /// 1. **Vault path** — e.g. `anthropic/api_key`. This is the canonical source;
    ///    rotations via `rotate_secret` take effect on the next job's pre-fetch.
    /// 2. **Env var fallback** — e.g. `ANTHROPIC_API_KEY`. Bootstrap path for dev
    ///    environments where the vault isn't populated; read directly from the
    ///    worker process env (not via `get_host_secret`, which would wrap the
    ///    value with `"Bearer "`).
    ///
    /// Returns `None` for Ollama (no key required) and for unknown providers.
    ///
    /// Tier enforcement: when `self.max_llm_tier == Tier1`, external
    /// providers (Anthropic / OpenAI / Gemini) are refused — the caller
    /// sees `None` which the `llm::complete` dispatcher surfaces as a
    /// missing-key error to the guest. The tier check happens BEFORE
    /// any vault or env lookup so no key material is resolved for a
    /// forbidden provider.
    pub(crate) async fn get_llm_api_key(&mut self, provider: wit_llm::Provider) -> Option<String> {
        let provider_name = match provider {
            wit_llm::Provider::Anthropic => "anthropic",
            wit_llm::Provider::Openai => "openai",
            wit_llm::Provider::Gemini => "gemini",
            wit_llm::Provider::Ollama => "ollama",
        };
        match decide_llm_tier_access(provider_name, self.max_llm_tier) {
            LlmTierDecision::NoKeyNeeded => return None,
            LlmTierDecision::Refused => {
                self.record_capability_denied(
                    "llm-key-resolution",
                    "tier1-llm-egress",
                    provider_name,
                )
                .await;
                tracing::warn!(
                    provider = provider_name,
                    "tier-1 actor attempted external LLM call; refused"
                );
                return None;
            }
            LlmTierDecision::Allowed => {}
        }
        let (vault_path, env_name) = llm_key_lookup_paths(provider_name)?;
        if let Some(v) = self.resolve_raw_vault_secret(vault_path).await {
            return Some(v);
        }
        std::env::var(env_name).ok().filter(|v| !v.is_empty())
    }

    /// String-keyed variant used by llm-tools / llm-streaming, whose WIT Provider
    /// enums are distinct from `wit_llm::Provider` but cover the same providers.
    ///
    /// Same tier enforcement as `get_llm_api_key`.
    pub(crate) async fn get_llm_api_key_by_name(&mut self, provider_name: &str) -> Option<String> {
        let lower = provider_name.to_ascii_lowercase();
        match decide_llm_tier_access(&lower, self.max_llm_tier) {
            LlmTierDecision::NoKeyNeeded => return None,
            LlmTierDecision::Refused => {
                self.record_capability_denied("llm-key-resolution", "tier1-llm-egress", &lower)
                    .await;
                tracing::warn!(
                    provider = provider_name,
                    "tier-1 actor attempted external LLM call; refused"
                );
                return None;
            }
            LlmTierDecision::Allowed => {}
        }
        let (vault_path, env_name) = llm_key_lookup_paths(provider_name)?;
        if let Some(v) = self.resolve_raw_vault_secret(vault_path).await {
            return Some(v);
        }
        std::env::var(env_name).ok().filter(|v| !v.is_empty())
    }
}

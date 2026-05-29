use async_graphql::Result;
use uuid::Uuid;

use crate::schema::SafeErrorExtensions;

/// MCP-1023 (2026-05-15): every validation error in this file MUST flow
/// through this helper so the production scrubber preserves the
/// operator-debuggable message verbatim. Pre-fix all 31 `async_graphql::
/// Error::new(...)` sites here returned bare errors. The controller
/// scrubber at `controller/main.rs:5042` replaces any error whose
/// `.extensions.safe` flag is unset AND whose message lacks one of the
/// six whitelist substrings (`Authentication` / `Access denied` /
/// `Not found` / `Invalid` / `Validation` / `Unauthorized`) with the
/// generic "Internal server error" string. Most validator messages here
/// — "Name cannot be empty", "Name exceeds maximum length", "Identifier
/// cannot start or end with a hyphen", "key_path must be 1-200
/// characters", etc. — match NONE of those substrings, so operators
/// shaping their input to fix one of these checks got back a useless
/// "Internal server error" in production.
///
/// Lint check 14 (MCP-916/918/963/964) explicitly excludes
/// `validation.rs:` because the lint sweep assumed validation messages
/// were ALWAYS operator-debuggable — they are, but they only reach the
/// operator if `.extend_safe()` is applied. This helper centralises that
/// guarantee so adding a new validator (or new error path inside an
/// existing one) automatically inherits the discipline.
fn safe_err(msg: impl Into<String>) -> async_graphql::Error {
    async_graphql::Error::new(msg).extend_safe()
}

const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10MB

/// Map a protocol-neutral [`talos_validation::ValidationError`] into the
/// GraphQL `safe_err` shape so the canonical message survives the
/// production scrubber (`.extend_safe()`). All three name/description
/// validators below delegate their predicate logic to `talos-validation`
/// — the rule + message live there once, this crate only adapts the
/// error type. See that crate's module docs for the drift-class history.
fn safe_validation_err(e: talos_validation::ValidationError) -> async_graphql::Error {
    safe_err(e.message)
}

pub fn validate_payload_size(name: &str, payload: &str) -> Result<()> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(safe_err(format!(
            "{} payload exceeds maximum size of 10MB",
            name
        )));
    }
    Ok(())
}

/// Validates a workflow, module, or template name.
///
/// Rules:
/// - Must be between 1 and 255 characters
/// - Cannot contain path traversal or shell injection characters
/// - Cannot be empty or whitespace-only
/// - Cannot start with a dot (hidden files)
pub fn validate_resource_name(name: &str) -> Result<()> {
    // Canonical rule + messages live in `talos-validation` (shared with
    // the MCP surface). MCP-751's control-char tightening and the
    // forbidden-char / reserved-name / dot-prefix diagnostics are all
    // enforced there now.
    talos_validation::validate_resource_name(name).map_err(safe_validation_err)
}

/// Validates a display name with focused content discipline.
///
/// Use this for display-style names (organizations, actors, webhook
/// triggers, modules) where the value is shown to users but is NOT
/// used as a filesystem identifier. For filesystem-style names
/// (workflows, module-as-file, templates) use `validate_resource_name`,
/// which additionally rejects path-traversal characters + names
/// starting with `.` + reserved Windows filenames — restrictions
/// that don't fit display names like ".NET Consulting" or "Conway".
///
/// Steps:
///   1. Trim leading/trailing whitespace.
///   2. Reject empty-after-trim (the dashboard "blank row" failure mode).
///   3. Cap length-after-trim at `max_len`.
///   4. Reject `\0` and control characters on the ORIGINAL (a name
///      that trims clean but had embedded `\0` in the middle is still
///      malicious — downstream UPDATEs crash with opaque Postgres
///      errors per MCP-431).
///
/// Returns the trimmed slice for the caller to shadow:
///
/// ```ignore
/// let name = validate_display_name("Webhook name", &input.name, 255)?;
/// ```
///
/// Closes the MCP-769 deferred sweep for non-resource display names
/// (organizations / webhooks / modules / actors). Same focused subset
/// as the inline check shipped in MCP-831 (`create_organization`).
pub fn validate_display_name<'a>(
    field_name: &str,
    name: &'a str,
    max_len: usize,
) -> Result<&'a str> {
    // Canonical single-line-name rule lives in `talos-validation`
    // (shared with the MCP surface). MCP-1151's newline rejection is
    // enforced there via `LineMode::SingleLine`.
    talos_validation::validate_display_name(field_name, name, max_len)
        .map_err(safe_validation_err)
}

/// Validates multi-line description content with focused 4-step discipline.
///
/// Returns the trimmed slice on success. Use this for multi-line description
/// fields (actor description, workflow-version description, secret description)
/// — distinct from [`validate_display_name`] which is for single-line display
/// names and rejects newlines.
///
/// Steps:
///   1. Trim leading/trailing whitespace.
///   2. Reject empty-after-trim with a "non-empty, non-whitespace" message
///      (per MCP-186/MCP-373 — `"   "` descriptions render as blank entries
///      that operators can't distinguish from "no description").
///   3. Cap length-after-trim at `max_len`.
///   4. Reject `\0` and control chars on the ORIGINAL, except `\t` / `\n` /
///      `\r` which are legitimate in multi-line text (MCP-431 class —
///      embedded `\0` survives trim and crashes downstream UPDATEs).
///
/// **Caller-side empty handling.** This helper does NOT short-circuit
/// `desc.is_empty()` to `None`. Different mutations have different
/// "empty means" semantics:
///   * create_actor / publish_workflow_version / create_secret: empty
///     string means "field omitted" → caller maps to `None`.
///   * update_actor: empty string means "explicitly clear this column" →
///     caller maps to `Some(String::new())`.
/// Each caller does its own None/empty short-circuit BEFORE invoking
/// this helper, mirroring the inline shape that has been the convention
/// since MCP-748 / MCP-747.
///
/// MCP-837 (2026-05-14): canonical home for the inline 4-step that lived
/// duplicated across create_actor (MCP-748), update_actor (MCP-748),
/// publish_workflow_version (MCP-747), and create_secret (MCP-833).
/// Same canonicalization pattern as MCP-832 ([`validate_display_name`]).
pub fn validate_description_content<'a>(
    field_name: &str,
    desc: &'a str,
    max_len: usize,
) -> Result<&'a str> {
    // Canonical multi-line-description rule lives in `talos-validation`
    // (shared with the MCP surface). The empty-string omit-hint variant
    // ("Omit the field to leave it blank.") is the default — GraphQL
    // callers do their own None/empty short-circuit BEFORE calling this.
    talos_validation::validate_multiline_description(field_name, desc, max_len, "")
        .map_err(safe_validation_err)
}

/// Validates that a string is a safe identifier (alphanumeric + hyphens/underscores).
/// Used for slugs, catalog names, etc.
pub fn validate_safe_identifier(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(safe_err("Identifier cannot be empty"));
    }

    if id.len() > 64 {
        return Err(safe_err(
            "Identifier exceeds maximum length of 64 characters",
        ));
    }

    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(safe_err(
            "Identifier must be alphanumeric with hyphens or underscores only",
        ));
    }

    // Cannot start or end with hyphen
    if id.starts_with('-') || id.ends_with('-') {
        return Err(safe_err(
            "Identifier cannot start or end with a hyphen",
        ));
    }

    Ok(())
}

/// Maximum length for generic string fields (1 MB to prevent DoS).
const MAX_STRING_FIELD_LENGTH: usize = 1024 * 1024;
/// Maximum JSON nesting depth (prevents deeply nested object DoS attacks)
const MAX_JSON_DEPTH: usize = 100;
/// Maximum length for short string fields like descriptions.
const MAX_SHORT_STRING_LENGTH: usize = 10_000;

/// Validates that a string field doesn't exceed maximum length.
/// Used to prevent DoS attacks via extremely large input strings.
pub fn validate_string_length(field_name: &str, value: &str, max_len: usize) -> Result<()> {
    if value.len() > max_len {
        return Err(safe_err(format!(
            "{} exceeds maximum length of {} characters (got {})",
            field_name,
            max_len,
            value.len()
        )));
    }
    Ok(())
}

/// Validates a generic text field with reasonable defaults.
pub fn validate_text_field(field_name: &str, value: &str) -> Result<()> {
    validate_string_length(field_name, value, MAX_STRING_FIELD_LENGTH)
}

/// Validates a short text field (like descriptions).
pub fn validate_short_text_field(field_name: &str, value: &str) -> Result<()> {
    validate_string_length(field_name, value, MAX_SHORT_STRING_LENGTH)
}

/// MCP-1003 (2026-05-15): canonical validation for the `key_path`
/// component of a secret. Originally mirrored the rules enforced by
/// the MCP `handle_set_secret` handler so the GraphQL and MCP surfaces
/// would accept the same shape. After MCP-1201 (2026-05-17) removed
/// the MCP write path, GraphQL is the sole live caller; the rules are
/// kept here because they encode the canonical `vault_path_permitted`
/// matcher's case-sensitivity / slash-shape contract.
///
/// Rules (sibling-handler parity):
///   * 1–200 characters
///   * Lowercase ASCII alphanumeric + `-` + `_` + `/` only
///   * No leading or trailing `/`
///   * No consecutive `//`
///
/// Pre-fix the GraphQL `create_secret` / `update_secret` /
/// `delete_secret` mutations used `validate_short_text_field` which
/// is length-only. A caller could submit `key_path: "API_KEY"`
/// (uppercase) or `key_path: "anthropic//api_key"` (consecutive
/// slashes) or `key_path: "anthropic/\0api_key"` (control char) via
/// GraphQL, and:
///   * the MCP path would refuse the same shape (drift)
///   * downstream `vault_path_permitted` matching is case-sensitive
///     and `//`-sensitive, so the secret would be effectively
///     unreachable by module configs that follow the documented
///     lowercase/single-slash convention
///   * control chars in the stored value land in operator logs and
///     dashboard rendering as invisible characters
///
/// Same cross-protocol-parity drift class as MCP-829 (whitespace-only
/// value) and MCP-750 (trim name at boundary) — every per-field
/// validation that lives on one side of the protocol surface eventually
/// needs to live on the other.
pub fn validate_vault_key_path(key_path: &str) -> Result<()> {
    // MCP-1150 (2026-05-16): delegate to the canonical helper in
    // `talos-secrets-manager`. MCP-1201 (2026-05-17): MCP-side secret
    // writers were removed, so GraphQL is the sole live caller — the
    // shared helper is still the right home because the secrets-manager
    // crate owns secret-storage validation as a layer concern. The
    // helper returns `Result<(), &'static str>`; we wrap into our
    // protocol-specific `safe_err` so the GraphQL response still uses
    // the .extend_safe() shape and the structured-error contract.
    talos_secrets_manager::validate_vault_key_path(key_path).map_err(safe_err)
}

/// MCP-1187 (2026-05-17): validate `expires_in_days` on `create_api_key`
/// is in a sane range.
///
/// Pre-fix the GraphQL `create_api_key` mutation bound `input.expires_
/// in_days: Option<i64>` straight into `talos_api_keys::create_api_key`
/// which passed it to `Utc::now() + chrono::Duration::days(days)`.
/// Three failure modes:
///   1. `i64::MAX` → `Duration::days(days)` overflows on the
///      `days * MILLIS_PER_DAY` multiplication; `checked_mul`
///      returns None and the downstream `unwrap` PANICS the API
///      thread. Admin-scoped + 2FA-gated, but a single admin paste
///      crashes the controller request.
///   2. Negative values produce `expires_at` in the past — the key
///      is unusable from the moment it's minted; the operator
///      receives "key created" success but can't use it.
///   3. Zero produces `expires_at = now` — key is unusable within
///      one tick.
///
/// 10 years (3650 days) matches workspace ceilings (audit-ledger
/// retention, secrets-rotation interval). Operators wanting truly
/// long-lived keys can pass None (no expiry). Same caller-supplied-
/// numeric-bound class as MCP-1173/1174/1175 (retry policy bounds),
/// MCP-1182 (max_concurrent_executions).
pub fn validate_api_key_expires_in_days(value: Option<i64>) -> Result<()> {
    if let Some(n) = value {
        if !(1..=3650).contains(&n) {
            return Err(safe_err(
                "Invalid expires_in_days: must be between 1 and 3650 (10 years), or null for non-expiring key",
            ));
        }
    }
    Ok(())
}

/// MCP-1186 (2026-05-17): canonical 64 KiB cap on encrypted-secret
/// values, mirroring `talos_mcp_handlers::utils::MAX_SECRET_VALUE_BYTES`
/// and `talos_actor_memory_service::MAX_VALUE_BYTES`.
///
/// The cap was originally introduced to close a cross-protocol drift
/// between GraphQL `validate_text_field` (1 MiB) and the MCP
/// `handle_set_secret` ceiling (64 KiB). After MCP-1201 removed the
/// MCP secret-write surface entirely, GraphQL is the sole writer; the
/// cap stays at 64 KiB because the original rationale (decrypted
/// plaintext lives in worker heap on every fetch — 1 MiB × fleet ×
/// secrets-heavy workflows = real memory pressure) is independent of
/// the protocol surface.
const MAX_SECRET_VALUE_BYTES: usize = 64 * 1024;

/// Canonical validation for an encrypted-secret value. Rules
/// (originally mirroring the now-removed MCP `handle_set_secret`
/// chain, retained as the GraphQL contract post-MCP-1201):
/// non-whitespace AND ≤ 64 KiB. Leading/trailing whitespace inside
/// the value is preserved (legitimate secrets like multi-line PEM
/// keys carry a trailing newline) — only the all-whitespace case
/// rejects.
pub fn validate_secret_value(value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(safe_err(
            "Secret value must contain non-whitespace characters",
        ));
    }
    if value.len() > MAX_SECRET_VALUE_BYTES {
        return Err(safe_err(format!(
            "Secret value exceeds maximum size of {} bytes (got {})",
            MAX_SECRET_VALUE_BYTES,
            value.len()
        )));
    }
    Ok(())
}

/// MCP-1182 (2026-05-17): validate workflow `max_concurrent_executions`
/// is in the canonical 1-100 range.
///
/// Sibling-parity with the MCP `set_concurrency_limit` handler at
/// `talos-mcp-handlers/src/platform.rs::handle_set_max_concurrent_
/// executions` and the GraphQL `set_concurrency_limit` mutation in
/// `platform/mutations.rs` — both enforce 1-100 since MCP-326. The
/// `create_workflow` and `update_workflow` GraphQL mutations were
/// the holdouts: they bound `input.max_concurrent_executions`
/// straight into the INSERT/UPDATE without any range check, so a
/// caller could set the cap to `i32::MAX` (effectively no cap —
/// bypasses the per-workflow throttle that protects the worker
/// fleet from a runaway dispatch loop) or to 0 / negative (DoS
/// their own workflow; admit_count helper collapses negatives to
/// 0). Same cross-protocol validation-drift class as MCP-829
/// (update_secret whitespace-only), MCP-1003 (GraphQL secret
/// key_path), MCP-186/431/769/918 (display-name discipline) —
/// every per-field rule that lives on one surface eventually needs
/// the same rule on the others.
pub fn validate_max_concurrent_executions(value: Option<i32>) -> Result<()> {
    if let Some(n) = value {
        if !(1..=100).contains(&n) {
            return Err(safe_err(
                "Invalid max_concurrent_executions: must be between 1 and 100, or null to clear",
            ));
        }
    }
    Ok(())
}

/// MCP-1216 (2026-05-18): cap on the workflow-level wall-clock timeout
/// read from graph_json's top-level `execution_timeout_secs` field.
///
/// Re-exported here for caller convenience; the canonical const lives
/// in `talos_workflow_types::MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS` so
/// MCP, GraphQL, and any future write surface share one cap. See that
/// definition for the design rationale.
pub use talos_workflow_types::MAX_WORKFLOW_EXECUTION_TIMEOUT_SECS;

/// GraphQL-flavored wrapper around the cross-protocol canonical
/// validator `talos_workflow_types::validate_graph_timeouts`.
/// Wraps the typed error in `safe_err` so the message reaches the
/// caller through the production scrubber.
///
/// MCP-1217 (2026-05-18): MCP `import_workflow` was the first
/// discovered drift — the bundle-based handler in
/// `talos-mcp-handlers/src/workflows.rs::handle_import_workflow`
/// persisted caller-supplied graph_json verbatim, bypassing this
/// GraphQL-side gate. The canonical pure validator was promoted to
/// `talos-workflow-types` so both surfaces enforce the cap from one
/// implementation. Any future write surface MUST delegate to the
/// canonical helper.
pub fn validate_workflow_execution_timeout(graph_json: &str) -> Result<()> {
    talos_workflow_types::validate_graph_timeouts(graph_json).map_err(safe_err)
}

/// Validates JSON string field (prevents massive JSON payloads and deep nesting).
pub fn validate_json_field(field_name: &str, value: &str) -> Result<()> {
    // JSON fields are limited to the max payload size
    if value.len() > MAX_PAYLOAD_SIZE {
        return Err(safe_err(format!(
            "{} exceeds maximum JSON payload size of {} bytes",
            field_name, MAX_PAYLOAD_SIZE
        )));
    }

    // Validate JSON depth to prevent nested DoS attacks
    if let Err(e) = validate_json_depth(value) {
        return Err(safe_err(format!(
            "{}: {:?}",
            field_name, e
        )));
    }

    Ok(())
}

/// Validates JSON nesting depth without fully parsing the JSON.
/// Uses a lightweight bracket counting approach for efficiency.
fn validate_json_depth(json_str: &str) -> Result<()> {
    let mut max_depth: usize = 0;
    let mut current_depth: usize = 0;
    let mut in_string = false;
    let mut escape_next = false;
    let chars = json_str.chars().peekable();

    for ch in chars {
        if escape_next {
            escape_next = false;
            continue;
        }

        if ch == '\\' && in_string {
            escape_next = true;
            continue;
        }

        if ch == '"' && !in_string {
            in_string = true;
        } else if ch == '"' && in_string {
            in_string = false;
        } else if !in_string && (ch == '{' || ch == '[') {
            current_depth += 1;
            max_depth = max_depth.max(current_depth);
            if max_depth > MAX_JSON_DEPTH {
                return Err(safe_err(format!(
                    "JSON nesting depth exceeds maximum of {}",
                    MAX_JSON_DEPTH
                )));
            }
        } else if !in_string && (ch == '}' || ch == ']') {
            current_depth = current_depth.saturating_sub(1);
        }
    }

    Ok(())
}

/// Validates an email address format.
///
/// MCP-1153 (2026-05-16): delegate to `talos_auth::validate_email_format`
/// — the canonical home for the regex + length cap. Pre-fix the SAME
/// regex + length cap was inlined here AND in talos-auth, each with
/// the same MCP-1010 length-first ordering and MCP-626/MCP-1061
/// LazyLock/OnceLock + `.expect()` hardening. Cross-crate drift
/// identical to MCP-1150 (vault key_path) and MCP-1152 (secret
/// namespace) — every future tweak had to land in both.
///
/// Layered post-check: the talos-api version additionally rejects
/// `..`, leading `.`, trailing `.` shapes. talos-auth's regex already
/// rejects those by construction (the pattern requires each domain
/// label to start AND end with `[a-zA-Z0-9]`, and `..` is impossible
/// because each label is non-empty), so the post-check is redundant
/// belt-and-braces. Kept for paranoia + matches the pre-fix behaviour
/// byte-for-byte from a caller perspective.
pub fn validate_email(email: &str) -> Result<()> {
    talos_auth::validate_email_format(email).map_err(safe_err)?;
    // Belt-and-braces — see doc-comment.
    if email.contains("..") || email.starts_with('.') || email.ends_with('.') {
        return Err(safe_err("Invalid email format"));
    }
    Ok(())
}

/// Validates a URL is safe (no javascript:, data:, or other dangerous schemes).
pub fn validate_safe_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Err(safe_err("URL cannot be empty"));
    }

    if url.len() > 2048 {
        return Err(safe_err(
            "URL exceeds maximum length of 2048 characters",
        ));
    }

    // Block dangerous URL schemes
    let dangerous_schemes = ["javascript:", "data:", "vbscript:", "file:", "ftp:"];
    let url_lower = url.to_lowercase();
    for scheme in &dangerous_schemes {
        if url_lower.starts_with(scheme) {
            return Err(safe_err(format!(
                "Dangerous URL scheme not allowed: {}",
                scheme
            )));
        }
    }

    Ok(())
}

// MCP-907 (2026-05-14): `validate_password_strength` was removed.
// The active password validator is `talos_auth::validate_password`
// (private to talos-auth, called from `AuthService::create_user` at
// signup time). The previously public stub in this module had been
// dead since extraction (zero call sites outside its own tests) and
// diverged from the active validator in two harmful ways:
//   (a) `max_len: 128` — bcrypt silently truncates inputs past 72
//       bytes, so passwords differing only in chars 73+ would hash
//       to the same value. Wiring this stub in would have created a
//       silent collision-of-strong-passwords class.
//   (b) `has_sequential_chars` did `window[0] - 1` on raw u8s; in
//       release builds this wraps on a null byte, in debug it panics.
// Strengthening the active policy is a separate decision (NIST
// 800-63B favours length + breach-list over char-class diversity)
// and should be made against the live `validate_password` call path,
// not by resurrecting this stub.

/// Validates that a UUID string is well-formed.
///
/// MCP-1036: cap the reflected `uuid_str` in the error message via
/// `bounded_preview` (canonical sweep MCP-1022/1029/1030/1031/1032).
/// A caller passing a multi-MB string would otherwise echo the
/// entire value back through the GraphQL error path; bounded
/// reflection keeps the response short and the message useful for
/// real typos (a 36-char UUID fits comfortably inside 64 bytes).
pub fn validate_uuid(uuid_str: &str) -> Result<Uuid> {
    Uuid::parse_str(uuid_str).map_err(|_| {
        safe_err(format!(
            "Invalid UUID format: {}",
            talos_text_util::bounded_preview(uuid_str, 64)
        ))
    })
}

#[cfg(test)]
mod additional_tests {
    use super::*;

    // Email validation tests
    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.user@example.co.uk").is_ok());
        assert!(validate_email("user+tag@example.com").is_ok());
    }

    #[test]
    fn test_validate_email_invalid() {
        assert!(validate_email("").is_err());
        assert!(validate_email("invalid").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
        assert!(validate_email("user..name@example.com").is_err());
        assert!(validate_email(".user@example.com").is_err());
    }

    #[test]
    fn test_validate_email_too_long() {
        let long_email = format!("a@{}.{}", "a".repeat(250), "com");
        assert!(validate_email(&long_email).is_err());
    }

    // URL validation tests
    #[test]
    fn test_validate_safe_url_valid() {
        assert!(validate_safe_url("https://example.com").is_ok());
        assert!(validate_safe_url("http://localhost:3000").is_ok());
        assert!(validate_safe_url("/relative/path").is_ok());
    }

    #[test]
    fn test_validate_safe_url_dangerous_schemes() {
        assert!(validate_safe_url("javascript:alert(1)").is_err());
        assert!(validate_safe_url("data:text/html,<script>alert(1)</script>").is_err());
        assert!(validate_safe_url("vbscript:msgbox(1)").is_err());
        assert!(validate_safe_url("file:///etc/passwd").is_err());
        assert!(validate_safe_url("ftp://example.com").is_err());
    }

    #[test]
    fn test_validate_safe_url_empty() {
        assert!(validate_safe_url("").is_err());
    }

    #[test]
    fn test_validate_safe_url_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(2040));
        assert!(validate_safe_url(&long_url).is_err());
    }

    // MCP-907 (2026-05-14): password-strength tests removed alongside
    // `validate_password_strength` itself. Active password tests live
    // in `talos-auth::tests` against `validate_password`.

    // UUID validation tests
    #[test]
    fn test_validate_uuid_valid() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_uuid("00000000-0000-0000-0000-000000000000").is_ok());
    }

    #[test]
    fn test_validate_uuid_invalid() {
        assert!(validate_uuid("invalid-uuid").is_err());
        assert!(validate_uuid("").is_err());
        assert!(validate_uuid("550e8400-e29b-41d4-a716").is_err()); // Too short
        assert!(validate_uuid("not-a-uuid-string").is_err());
    }

    // Resource name validation tests
    #[test]
    fn test_validate_resource_name_valid() {
        assert!(validate_resource_name("my-workflow").is_ok());
        assert!(validate_resource_name("test_123").is_ok());
        assert!(validate_resource_name("A").is_ok());
    }

    #[test]
    fn test_validate_resource_name_invalid_chars() {
        assert!(validate_resource_name("path/traversal").is_err());
        assert!(validate_resource_name("..hidden").is_err());
        assert!(validate_resource_name("windows<file>").is_err());
        assert!(validate_resource_name("with|pipe").is_err());
    }

    #[test]
    fn test_validate_resource_name_reserved() {
        assert!(validate_resource_name("CON").is_err());
        assert!(validate_resource_name("com1").is_err());
        assert!(validate_resource_name("LPT1").is_err());
    }

    #[test]
    fn test_validate_resource_name_empty() {
        assert!(validate_resource_name("").is_err());
        assert!(validate_resource_name("   ").is_err());
    }

    #[test]
    fn test_validate_resource_name_hidden() {
        assert!(validate_resource_name(".hidden").is_err());
        assert!(validate_resource_name("..parent").is_err());
    }

    /// MCP-751: control chars beyond the FORBIDDEN_NAME_CHARS shortlist.
    /// `\0`, `\n`, `\r` already rejected via FORBIDDEN_NAME_CHARS with the
    /// "forbidden character" diagnostic (covered by validation_tests.rs);
    /// the long tail (BS, VT, FF, BEL, SOH, DEL, ...) is rejected by the
    /// post-FORBIDDEN_NAME_CHARS `is_control()` check with the
    /// "control characters" diagnostic. Matches MCP
    /// `validate_name_no_control_chars` (MCP-405/MCP-410).
    #[test]
    fn test_validate_resource_name_rejects_control_chars() {
        for c in [
            '\x01', '\x07', '\x08', '\x0B', '\x0C', '\x0E', '\x1F', '\x7F',
        ] {
            let name = format!("ab{}cd", c);
            let result = validate_resource_name(&name);
            assert!(
                result.is_err(),
                "expected rejection for control char {:?}",
                c
            );
            assert!(
                result.unwrap_err().message.contains("control character"),
                "expected control-char diagnostic for {:?}",
                c
            );
        }
        // Tab is permitted (matches MCP rule; legitimate names may include it).
        assert!(validate_resource_name("ab\tcd").is_ok());
    }

    // MCP-1003: vault key_path validation must mirror the MCP handler's
    // rules exactly. Each case below either accepts a legitimate shape
    // documented in the MCP handler's tool schema or rejects a shape
    // the MCP handler refuses.

    #[test]
    fn validate_vault_key_path_accepts_canonical_shapes() {
        for p in [
            "anthropic/api_key",
            "database/connection_url",
            "api/stripe/key",
            "github_pat",
            "k", // single char, min length
            "api123/v2/key_alpha-beta",
        ] {
            assert!(validate_vault_key_path(p).is_ok(), "must accept: {p}");
        }
    }

    #[test]
    fn validate_vault_key_path_rejects_uppercase() {
        // MCP handler is lowercase-only; GraphQL must match.
        let err = validate_vault_key_path("API_KEY").unwrap_err();
        assert!(err.message.contains("lowercase"), "got: {}", err.message);
    }

    #[test]
    fn validate_vault_key_path_rejects_empty_and_oversize() {
        assert!(validate_vault_key_path("").is_err());
        let oversize = "a".repeat(201);
        assert!(validate_vault_key_path(&oversize).is_err());
        // 200 chars is the boundary — must accept.
        let max = "a".repeat(200);
        assert!(validate_vault_key_path(&max).is_ok());
    }

    #[test]
    fn validate_vault_key_path_rejects_leading_trailing_slash() {
        for bad in ["/anthropic/api_key", "anthropic/api_key/", "/"] {
            let err = validate_vault_key_path(bad).unwrap_err();
            assert!(
                err.message.contains("start or end with '/'") || err.message.contains("consecutive"),
                "rejected {bad} for wrong reason: {}",
                err.message
            );
        }
    }

    #[test]
    fn validate_vault_key_path_rejects_consecutive_slashes() {
        let err = validate_vault_key_path("anthropic//api_key").unwrap_err();
        assert!(
            err.message.contains("consecutive slashes"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn validate_vault_key_path_rejects_control_chars() {
        // The charset gate triggers first — control chars aren't in
        // [a-z0-9-_/], so the "lowercase alphanumeric..." diagnostic
        // fires. Either way the rejection is enforced.
        for bad in ["api\0key", "api\x01key", "api\x7fkey"] {
            assert!(validate_vault_key_path(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn validate_vault_key_path_rejects_path_traversal_shapes() {
        // `..` itself contains a `.` which is not in the allowed set;
        // the charset check catches it. Confirms the helper handles
        // the most-common path-traversal shape attackers reach for.
        for bad in ["../secrets", "anthropic/..", "a.b", "a b", "a:b"] {
            assert!(validate_vault_key_path(bad).is_err(), "must reject {bad:?}");
        }
    }

    /// MCP-1151 (2026-05-16): `\n` rejected by `validate_display_name`
    /// to match the MCP-side canonical `validate_name_no_control_chars`.
    #[test]
    fn validate_display_name_rejects_newline_for_cross_protocol_parity() {
        // Pre-fix accepted; post-fix rejected. Pins the MCP-1151 tightening.
        let err = validate_display_name("Actor name", "Line1\nLine2", 100).unwrap_err();
        assert!(
            err.message.contains("control characters"),
            "expected control-char rejection, got: {}",
            err.message
        );
        let err2 = validate_display_name("Org name", "Org\nNewline", 255).unwrap_err();
        assert!(err2.message.contains("control characters"));
    }

    #[test]
    fn validate_display_name_accepts_tab_but_not_other_controls() {
        // Tab stays allowed (paste-from-spreadsheet case).
        assert!(validate_display_name("Module", "My\tModule", 100).is_ok());
        // Carriage return rejected.
        assert!(validate_display_name("Module", "My\rModule", 100).is_err());
        // Bell rejected.
        assert!(validate_display_name("Module", "My\x07Module", 100).is_err());
        // Null rejected.
        assert!(validate_display_name("Module", "My\0Module", 100).is_err());
    }

    #[test]
    fn validate_display_name_accepts_canonical_names() {
        for name in [
            "My Workflow",
            "Actor 1",
            "Org-Name_42",
            "Tab\there",
            "Acme Corp",
            ".NET Consulting",
        ] {
            assert!(
                validate_display_name("Test", name, 100).is_ok(),
                "must accept canonical name: {name}"
            );
        }
    }
}
#[cfg(test)]
#[path = "validation_tests.rs"]
mod validation_tests;

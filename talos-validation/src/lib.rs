//! Canonical, protocol-neutral field validators shared by every write
//! surface (GraphQL `talos-api`, MCP `talos-mcp-handlers`, and any future
//! protocol). Each function returns a [`ValidationError`] carrying the
//! canonical operator-facing message; the calling surface maps that into
//! its own error type (`async_graphql::Error::extend_safe()` for GraphQL,
//! `mcp_error(-32602, …)` for MCP).
//!
//! # Why this crate exists
//!
//! For most of the project's history these validators were duplicated
//! per protocol surface — `talos-api/src/validation.rs` returned
//! `async_graphql::Error`, `talos-mcp-handlers/src/utils.rs` returned a
//! `JsonRpcResponse`, and the predicate logic + message text was copied
//! between them. Every per-field rule that landed on one surface
//! eventually had to be mirrored on the other, and the sweep kept
//! missing sites: MCP-1003 (vault key_path uppercase/slash shape),
//! MCP-963/964 (`.extend_safe()` whitelist), MCP-1151 (newline in display
//! name), MCP-998 (RBAC drift on the sibling query). The fix that finally
//! sticks is structural: the rule and its message live **once**, here, so
//! a fix physically cannot land on one surface and miss the other.
//!
//! `scripts/lint-structural.sh` (check 21) flags any inline re-derivation
//! of the control-char/null-byte predicate outside this crate, so new
//! drift fails at PR time rather than in a future audit.
//!
//! # Message stability
//!
//! The message strings produced here are part of the contract: existing
//! GraphQL and MCP tests assert on substrings of them (`"control
//! characters"`, `"cannot be empty"`, `"must be ≤"`, …). Treat a message
//! change as a behaviour change — update the wrappers' tests in lockstep.

use thiserror::Error;

/// Maximum length for human-supplied resource names (workflows, modules,
/// templates). Mirrored by `talos_mcp_handlers::utils::MAX_NAME_LENGTH`
/// and the GraphQL `MAX_NAME_LENGTH`.
pub const MAX_NAME_LENGTH: usize = 255;

/// Minimum length for a resource name (a single non-whitespace char).
pub const MIN_NAME_LENGTH: usize = 1;

/// Characters not allowed in filesystem-style resource names — path
/// traversal (`/`, `\`), shell/Windows reserved (`<>:"|?*`), and the
/// three control chars that get a specific "forbidden character"
/// diagnostic for backwards-compatible test assertions (`\0`, `\n`,
/// `\r`). The long tail of control characters is caught by the
/// `is_control()` sweep in [`validate_resource_name`].
const FORBIDDEN_NAME_CHARS: &[char] =
    &['/', '\\', '<', '>', ':', '"', '|', '?', '*', '\0', '\n', '\r'];

/// Reserved Windows device filenames — rejected as resource names because
/// a workflow/module persisted under one of these breaks on any operator
/// who later exports to a Windows filesystem.
const RESERVED_WINDOWS_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// A protocol-neutral validation failure. The wrapping surface maps
/// [`ValidationError::message`] into its own error type.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct ValidationError {
    /// Canonical, operator-facing message. Safe to surface to clients —
    /// it describes the input rule, never internal state.
    pub message: String,
}

impl ValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Whether a field may contain line breaks. Single-line names (workflow
/// name, actor name, secret name) reject `\n`/`\r`; multi-line text
/// (descriptions) allows them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineMode {
    /// Reject every control char except tab (`\t`). `\n` and `\r` are
    /// control chars, so they are rejected.
    SingleLine,
    /// Reject control chars except tab/newline/carriage-return
    /// (`\t`, `\n`, `\r`) — legitimate in multi-line free text.
    MultiLine,
}

/// Reject `\0` and disallowed control characters in `value`.
///
/// Operates on the value **as given** (the caller has NOT trimmed it):
/// an embedded `\0` survives `.trim()` and lands in Postgres as an
/// opaque "invalid byte sequence" error downstream (MCP-431), so the
/// check must see the original bytes.
///
/// The diagnostic is `"{field} cannot contain control characters or null
/// bytes"` — identical on both protocol surfaces.
pub fn reject_control_chars(field: &str, value: &str, mode: LineMode) -> Result<(), ValidationError> {
    let has_bad = value.contains('\0')
        || value.chars().any(|c| match mode {
            LineMode::SingleLine => c.is_control() && c != '\t',
            LineMode::MultiLine => c.is_control() && c != '\t' && c != '\n' && c != '\r',
        });
    if has_bad {
        return Err(ValidationError::new(format!(
            "{field} cannot contain control characters or null bytes"
        )));
    }
    Ok(())
}

/// Validate a single-line display name and return the trimmed slice.
///
/// Steps (order matters — empty/length on the trimmed value, control-char
/// check on the ORIGINAL so embedded `\0` can't slip through a trim):
///   1. Trim; reject empty-after-trim.
///   2. Reject length-after-trim > `max_len`.
///   3. Reject `\0` and control chars (newlines rejected — single line).
///
/// Use for organization / actor / module / webhook names. For
/// filesystem-style names (workflows, templates) use
/// [`validate_resource_name`], which additionally bans path-traversal
/// chars, leading dots, and reserved Windows filenames.
pub fn validate_display_name<'a>(
    field: &str,
    value: &'a str,
    max_len: usize,
) -> Result<&'a str, ValidationError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::new(format!(
            "{field} cannot be empty or whitespace-only"
        )));
    }
    if trimmed.len() > max_len {
        return Err(ValidationError::new(format!(
            "{field} must be 1–{max_len} characters"
        )));
    }
    reject_control_chars(field, value, LineMode::SingleLine)?;
    Ok(trimmed)
}

/// Validate a multi-line description and return the trimmed slice.
///
/// Steps:
///   1. Trim; reject empty-after-trim (whitespace-only) with a message
///      ending in `omit_hint` (pass `""` for the default
///      "Omit the field to leave it blank." phrasing).
///   2. Reject length-after-trim > `max_len`.
///   3. Reject `\0` and control chars on the ORIGINAL, allowing
///      `\t`/`\n`/`\r` (legitimate in multi-line text).
///
/// The caller owns the `None`/empty-string → "field omitted" mapping —
/// different mutations attach different "empty means" semantics
/// (clear-the-column vs. leave-unset), so this helper only sees a
/// non-empty `&str`.
pub fn validate_multiline_description<'a>(
    field: &str,
    value: &'a str,
    max_len: usize,
    omit_hint: &str,
) -> Result<&'a str, ValidationError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        let msg = if omit_hint.is_empty() {
            format!(
                "{field} must be non-empty and non-whitespace when provided. \
                 Omit the field to leave it blank."
            )
        } else {
            format!("{field} must be non-empty and non-whitespace when provided. {omit_hint}")
        };
        return Err(ValidationError::new(msg));
    }
    if trimmed.len() > max_len {
        return Err(ValidationError::new(format!(
            "{field} must be ≤ {max_len} characters"
        )));
    }
    reject_control_chars(field, value, LineMode::MultiLine)?;
    Ok(trimmed)
}

/// Validate a filesystem-style resource name (workflow, module, template).
///
/// Rules (checked on the trimmed value):
///   - 1..=255 characters, non-empty after trim
///   - no path-traversal / shell / Windows-reserved characters
///   - no ASCII control characters except tab
///   - cannot start with `.` (hidden file)
///   - cannot be a reserved Windows device name (con, lpt1, …)
pub fn validate_resource_name(name: &str) -> Result<(), ValidationError> {
    let trimmed = name.trim();
    if trimmed.len() < MIN_NAME_LENGTH {
        return Err(ValidationError::new("Name cannot be empty or whitespace-only"));
    }
    if trimmed.len() > MAX_NAME_LENGTH {
        return Err(ValidationError::new(format!(
            "Name exceeds maximum length of {MAX_NAME_LENGTH} characters"
        )));
    }
    if let Some(forbidden) = trimmed.chars().find(|c| FORBIDDEN_NAME_CHARS.contains(c)) {
        return Err(ValidationError::new(format!(
            "Name contains forbidden character: '{forbidden}'"
        )));
    }
    // Long tail of control chars beyond the FORBIDDEN_NAME_CHARS shortlist
    // (BEL, BS, VT, FF, SOH, DEL, …); tab stays allowed.
    if trimmed.chars().any(|c| c.is_control() && c != '\t') {
        return Err(ValidationError::new("Name cannot contain control characters"));
    }
    if trimmed.starts_with('.') {
        return Err(ValidationError::new("Name cannot start with a dot (.)"));
    }
    if RESERVED_WINDOWS_NAMES.contains(&trimmed.to_lowercase().as_str()) {
        return Err(ValidationError::new("Name is a reserved system filename"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- reject_control_chars --------------------------------------

    #[test]
    fn single_line_rejects_newline_and_other_controls_but_allows_tab() {
        assert!(reject_control_chars("F", "a\tb", LineMode::SingleLine).is_ok());
        for bad in ["a\nb", "a\rb", "a\x07b", "a\x00b", "a\x7fb"] {
            assert!(
                reject_control_chars("F", bad, LineMode::SingleLine).is_err(),
                "single-line must reject {bad:?}"
            );
        }
    }

    #[test]
    fn multiline_allows_newline_and_cr_but_rejects_other_controls() {
        for ok in ["a\tb", "a\nb", "a\r\nb"] {
            assert!(
                reject_control_chars("F", ok, LineMode::MultiLine).is_ok(),
                "multi-line must accept {ok:?}"
            );
        }
        for bad in ["a\x07b", "a\x00b", "a\x0bb", "a\x7fb"] {
            assert!(
                reject_control_chars("F", bad, LineMode::MultiLine).is_err(),
                "multi-line must reject {bad:?}"
            );
        }
    }

    #[test]
    fn control_char_message_is_stable() {
        let e = reject_control_chars("Actor name", "x\x07y", LineMode::SingleLine).unwrap_err();
        assert_eq!(e.message, "Actor name cannot contain control characters or null bytes");
    }

    // ---- validate_display_name -------------------------------------

    #[test]
    fn display_name_accepts_canonical_and_returns_trimmed() {
        assert_eq!(validate_display_name("N", "  Acme Corp  ", 255).unwrap(), "Acme Corp");
        for ok in ["My Workflow", "Actor 1", "Org-Name_42", ".NET Consulting", "Tab\there"] {
            assert!(validate_display_name("N", ok, 255).is_ok(), "must accept {ok:?}");
        }
    }

    #[test]
    fn display_name_rejects_empty_oversize_and_newline() {
        assert!(validate_display_name("N", "   ", 255).is_err());
        assert!(validate_display_name("N", &"a".repeat(256), 255).is_err());
        assert!(validate_display_name("N", "Line1\nLine2", 255).is_err());
        // embedded null survives trim
        assert!(validate_display_name("N", " a\0b ", 255).is_err());
    }

    #[test]
    fn display_name_messages_are_stable() {
        assert_eq!(
            validate_display_name("Org name", "  ", 255).unwrap_err().message,
            "Org name cannot be empty or whitespace-only"
        );
        assert_eq!(
            validate_display_name("Org name", &"a".repeat(10), 5).unwrap_err().message,
            "Org name must be 1–5 characters"
        );
    }

    // ---- validate_multiline_description ----------------------------

    #[test]
    fn multiline_accepts_newlines_and_returns_trimmed() {
        assert_eq!(
            validate_multiline_description("D", "  line1\nline2  ", 10_000, "").unwrap(),
            "line1\nline2"
        );
    }

    #[test]
    fn multiline_empty_message_uses_default_or_custom_hint() {
        assert_eq!(
            validate_multiline_description("D", "   ", 10_000, "").unwrap_err().message,
            "D must be non-empty and non-whitespace when provided. \
             Omit the field to leave it blank."
        );
        assert_eq!(
            validate_multiline_description("D", "   ", 10_000, "Pass null to inherit.")
                .unwrap_err()
                .message,
            "D must be non-empty and non-whitespace when provided. Pass null to inherit."
        );
    }

    #[test]
    fn multiline_length_message_is_stable() {
        assert_eq!(
            validate_multiline_description("D", &"a".repeat(11), 10, "").unwrap_err().message,
            "D must be ≤ 10 characters"
        );
    }

    // ---- validate_resource_name ------------------------------------

    #[test]
    fn resource_name_accepts_valid() {
        for ok in ["my-workflow", "test_123", "A"] {
            assert!(validate_resource_name(ok).is_ok(), "must accept {ok:?}");
        }
    }

    #[test]
    fn resource_name_rejects_traversal_hidden_reserved_and_controls() {
        assert!(validate_resource_name("path/traversal").is_err());
        assert!(validate_resource_name(".hidden").is_err());
        assert!(validate_resource_name("with|pipe").is_err());
        assert!(validate_resource_name("CON").is_err());
        assert!(validate_resource_name("lpt1").is_err());
        assert!(validate_resource_name("").is_err());
        assert!(validate_resource_name("   ").is_err());
        // control char beyond the forbidden shortlist → "control characters"
        let e = validate_resource_name("ab\x07cd").unwrap_err();
        assert_eq!(e.message, "Name cannot contain control characters");
        // tab permitted
        assert!(validate_resource_name("ab\tcd").is_ok());
    }

    #[test]
    fn resource_name_forbidden_char_message_is_stable() {
        let e = validate_resource_name("a/b").unwrap_err();
        assert_eq!(e.message, "Name contains forbidden character: '/'");
    }
}

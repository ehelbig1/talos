//! Input sanitization utilities for preventing log injection and XSS.
//!
//! This module provides:
//! - Log injection prevention (`sanitize_for_logging`)
//! - Secret masking in log strings (`mask_secrets`)
//!
//! MCP-910 (2026-05-14): `sanitize_user_input`, `safe_truncate`, and
//! `sanitize_identifier` were removed — zero non-test callers since
//! crate extraction and the file-level `#![allow(dead_code)]` was
//! masking them. `sanitize_for_logging` covers the log-render path
//! (the only consumer of these helpers in practice); persistence-
//! side sanitization belongs in `talos-dlp` per the
//! `persistence_boundary_dlp_rule.md` invariant.

/// Characters that could be used for log injection or terminal escape sequences.
///
/// MCP-506: predicate-based check rather than a fixed list. The
/// previous fixed-size array missed two real attack surfaces:
///   * U+007F (DEL) — some terminals render as backspace.
///   * U+0080..U+009F (C1 control range) — includes U+009B which is a
///     single-byte CSI alternative to ESC-[ that some terminals
///     interpret as a control-sequence introducer. A 7-bit-only ESC
///     filter wouldn't catch it.
/// Tab / LF / CR are explicitly preserved (and LF/CR are escaped to
/// `\n`/`\r` literals later) — they're normal text content.
fn is_dangerous_log_char(c: char) -> bool {
    match c {
        '\t' | '\n' | '\r' => false,
        // C0 controls (U+0000..U+001F), DEL (U+007F), and C1 controls (U+0080..U+009F).
        c if (c as u32) <= 0x1F => true,
        '\u{007F}' => true,
        c if (0x80..=0x9F).contains(&(c as u32)) => true,
        _ => false,
    }
}

/// ANSI escape sequence patterns
const ANSI_ESCAPE_REGEX: &str = r"\x1b\[[0-9;]*m";

/// Compiled regex for ANSI escape sequences.
static ANSI_ESCAPE_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(ANSI_ESCAPE_REGEX).expect("valid ANSI escape regex")
});

/// Sanitize a string for safe logging.
pub fn sanitize_for_logging(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    let mut result = ANSI_ESCAPE_RE.replace_all(input, "").to_string();

    result = result
        .chars()
        .filter(|c| !is_dangerous_log_char(*c))
        .collect();

    result.replace('\n', "\\n").replace('\r', "\\r")
}

/// MCP-506: pre-compile the mask patterns once. Pre-fix `mask_secrets`
/// called `Regex::new` three times per invocation — regex compilation
/// is in the millisecond range and this helper is intended for the
/// log-render hot path. `LazyLock` matches the ANSI_ESCAPE_RE pattern
/// above it.
///
/// Pattern set: Bearer-style, api-key= form, password= form. NOT a
/// substitute for talos-dlp / talos-dlp-provider scrubbing at the
/// DB-persistence boundary — see `persistence_boundary_dlp_rule.md`.
/// This helper is for OPERATOR-VISIBLE log strings only, where the
/// canonical DLP path is bypassed by `tracing::warn!` macros that
/// don't go through the SQL persistence boundary.
///
/// MCP-543: the bearer pattern uses `[^\s,;)\]"']+` instead of `\w+`
/// for the token body. JWTs ARE valid bearer tokens and contain `.`
/// as the segment separator — `\w+` (which is `[A-Za-z0-9_]`) stops
/// at the first `.`, leaving the JWT signature half visible in logs.
/// Same gap for any token format using `-`, `=`, `/`, `+` (base64),
/// or hex with embedded `:` (`talos_sk_...:...`). The new character
/// class accepts everything except common log-delimiter punctuation,
/// matching the api-key and password patterns' `[^\s&]+` approach.
static MASK_PATTERNS: std::sync::LazyLock<[(regex::Regex, &'static str); 3]> =
    std::sync::LazyLock::new(|| {
        [
            (
                regex::Regex::new(r#"(?i)(bearer\s+)[^\s,;)\]"']+"#).expect("valid bearer regex"),
                "${1}***",
            ),
            (
                regex::Regex::new(r"(?i)(api[_-]?key\s*=\s*)[^\s&]+").expect("valid api-key regex"),
                "${1}***",
            ),
            (
                regex::Regex::new(r"(?i)(password\s*[=:]\s*)[^\s&]+")
                    .expect("valid password regex"),
                "${1}***",
            ),
        ]
    });

/// Mask sensitive data in strings.
pub fn mask_secrets(input: &str) -> String {
    let mut result = std::borrow::Cow::Borrowed(input);
    for (re, replacement) in MASK_PATTERNS.iter() {
        // `replace_all` returns Cow::Borrowed when no match, so the
        // hot path of clean strings is allocation-free.
        match re.replace_all(&result, *replacement) {
            std::borrow::Cow::Borrowed(_) => {} // no match — keep `result` as-is
            std::borrow::Cow::Owned(s) => result = std::borrow::Cow::Owned(s),
        }
    }
    result.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_for_logging() {
        let input = "\x1b[31mRed\x1b[0m text";
        assert_eq!(sanitize_for_logging(input), "Red text");
    }

    #[test]
    fn test_mask_secrets() {
        let input = "Authorization: Bearer secret_token_123";
        let masked = mask_secrets(input);
        assert!(!masked.contains("secret_token"));
    }

    /// MCP-506: U+007F (DEL) is a terminal control character that some
    /// renderers display as backspace. Must be stripped from log
    /// output. Pre-fix the fixed `DANGEROUS_CHARS` array did not
    /// include it.
    #[test]
    fn sanitize_strips_del_character() {
        let input = "hello\u{007F}world";
        let sanitized = sanitize_for_logging(input);
        assert_eq!(sanitized, "helloworld");
    }

    /// MCP-506: U+0080..U+009F are the C1 control range. U+009B
    /// specifically is a single-byte CSI alternative — some terminals
    /// honor it as a control-sequence introducer without needing the
    /// 7-bit ESC-[ form. Strip the whole C1 range from log output.
    #[test]
    fn sanitize_strips_c1_control_range() {
        // U+009B (single-byte CSI) followed by what would otherwise
        // be a screen-clear sequence.
        let input = "before\u{009B}2J after";
        let sanitized = sanitize_for_logging(input);
        // U+009B is stripped; the literal "2J" remains as text.
        assert!(
            !sanitized.contains('\u{009B}'),
            "U+009B must be stripped, got {:?}",
            sanitized
        );
        // Spot-check a few other C1 codepoints.
        for c in ['\u{0080}', '\u{0085}', '\u{0090}', '\u{009F}'] {
            let s = format!("a{}b", c);
            let out = sanitize_for_logging(&s);
            assert!(
                !out.contains(c),
                "C1 codepoint {:?} (U+{:04X}) must be stripped, got {:?}",
                c,
                c as u32,
                out
            );
        }
    }

    /// MCP-506: tab / LF / CR are normal text. Tab stays as-is;
    /// LF / CR get escaped to literal \n / \r tokens so multi-line
    /// log injection can't sneak through.
    #[test]
    fn sanitize_preserves_tab_and_escapes_newlines() {
        let input = "col1\tcol2\nrow2\rcr";
        let sanitized = sanitize_for_logging(input);
        assert_eq!(sanitized, "col1\tcol2\\nrow2\\rcr");
    }

    /// MCP-506: pre-compile path returns the same masked output as
    /// the old per-call compile. Pins behavior across the refactor.
    #[test]
    fn mask_secrets_preserves_all_patterns() {
        assert_eq!(
            mask_secrets("Authorization: Bearer abc123"),
            "Authorization: Bearer ***"
        );
        assert_eq!(
            mask_secrets("?api_key=secret&other=x"),
            "?api_key=***&other=x"
        );
        assert_eq!(mask_secrets("password=hunter2"), "password=***");
        // Clean input fast-path: returns identical content.
        assert_eq!(mask_secrets("nothing secret here"), "nothing secret here");
    }

    /// MCP-543: JWTs are valid bearer tokens and contain `.` as the
    /// segment separator. Pre-fix the regex `\w+` (which is
    /// `[A-Za-z0-9_]`, no dot) stopped at the first `.`, leaving the
    /// payload + signature halves visible in logs.
    #[test]
    fn mask_secrets_redacts_full_jwt_bearer_token() {
        // 3-segment JWT (header.payload.signature). Real-world shape.
        let jwt =
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let input = format!("Authorization: Bearer {}", jwt);
        let masked = mask_secrets(&input);
        assert!(
            !masked.contains("eyJzdWIiOiIxMjM0NTY3ODkwIn0"),
            "JWT payload segment must be masked, got {:?}",
            masked
        );
        assert!(
            !masked.contains("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
            "JWT signature segment must be masked, got {:?}",
            masked
        );
        assert_eq!(masked, "Authorization: Bearer ***");
    }

    /// MCP-543: other realistic token shapes that `\w+` would have
    /// truncated. Talos's own session tokens use `talos_sk_<prefix><secret>`
    /// which is all-word — safe under either pattern — but rotated
    /// formats and third-party tokens (Anthropic `sk-ant-...`,
    /// Stripe `sk_live_...`, GitHub `ghp_...`) commonly include
    /// non-word chars.
    #[test]
    fn mask_secrets_redacts_dashed_and_slashed_tokens() {
        for (input, want_not_in_output) in [
            (
                "Authorization: Bearer sk-ant-api03-AbCdEfGh.IjKlMnOp",
                "IjKlMnOp",
            ),
            ("Authorization: Bearer base64+slash/eq=", "base64+slash/eq="),
            ("Authorization: Bearer hex:abc:def:123", "hex:abc:def:123"),
            (
                "Authorization: Bearer xoxb-foo-bar.baz_quux",
                "xoxb-foo-bar.baz_quux",
            ),
        ] {
            let out = mask_secrets(input);
            assert!(
                !out.contains(want_not_in_output),
                "should mask the FULL token {:?}, but {:?} survived: {:?}",
                input,
                want_not_in_output,
                out
            );
        }
    }

    /// MCP-543: log-delimiter boundary still works. The new character
    /// class `[^\s,;)\]"']+` MUST stop at common log delimiters so we
    /// don't eat the rest of the log line. Comma + closing brackets +
    /// quote characters all delimit a token from surrounding context.
    #[test]
    fn mask_secrets_stops_at_log_delimiters() {
        for (input, want) in [
            (
                "msg=\"auth failed Bearer abc.def\", err=timeout",
                "msg=\"auth failed Bearer ***\", err=timeout",
            ),
            ("context: (Bearer xyz_abc.def_xyz)", "context: (Bearer ***)"),
            (
                "trace=[Bearer t1.t2.t3] continued",
                "trace=[Bearer ***] continued",
            ),
        ] {
            let out = mask_secrets(input);
            assert_eq!(out, want, "delimiter boundary failed for input {:?}", input);
        }
    }
}

//! SQL-input safety helpers shared by the semantic-search chain and
//! its callers.

/// Escape PostgreSQL LIKE/ILIKE metacharacters in a user-supplied
/// search term. `%` and `_` are wildcards; `\` is the escape
/// character. The result is safe to wrap with outer `%` wildcards:
/// `format!("%{}%", escape_like(q))`.
#[inline]
pub fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_like_handles_metacharacters() {
        assert_eq!(escape_like(r"a%b"), r"a\%b");
        assert_eq!(escape_like("a_b"), r"a\_b");
        assert_eq!(escape_like(r"a\b"), r"a\\b");
    }

    #[test]
    fn escape_like_passthrough_when_clean() {
        assert_eq!(escape_like("hello world"), "hello world");
        assert_eq!(escape_like("api.openai.com"), "api.openai.com");
    }

    #[test]
    fn escape_like_escapes_backslash_first_so_metas_dont_double() {
        // The replacement order matters: backslash must be doubled
        // BEFORE we introduce new backslashes via `%` / `_` escaping.
        // Otherwise `%` becomes `\%` and the following backslash-pass
        // doubles it to `\\%` — corrupting the pattern.
        assert_eq!(escape_like(r"%"), r"\%");
        assert_eq!(escape_like(r"_"), r"\_");
    }
}

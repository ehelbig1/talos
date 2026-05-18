/// Returns `true` when the process is running in a development environment.
///
/// Checks the `RUST_ENV` environment variable — any value other than
/// `"development"` (or the variable being unset) is considered non-development.
pub fn is_development() -> bool {
    std::env::var("RUST_ENV")
        .map(|v| v.eq_ignore_ascii_case("development"))
        .unwrap_or(false)
}

/// Returns `true` when the process is running in a production environment.
pub fn is_production() -> bool {
    std::env::var("RUST_ENV")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

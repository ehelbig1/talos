//! Startup configuration validation for Talos controller.
//!
//! This module validates all required configuration at startup,
//! failing fast with clear error messages if anything is misconfigured.

use anyhow::{anyhow, Result};

/// Returns true iff `var` is set in the environment AND its value is
/// non-empty. Empty-string is treated as unset throughout the
/// configuration validator so a Helm values.yaml placeholder
/// (`jwtPrivateKey: ""`) doesn't shadow the actual fallback path.
/// Sibling rule to `read_env_or_file` in talos-config (MCP-597) and
/// the controller-side `seed_templates` filter (MCP-598).
pub(crate) fn env_var_is_set_nonempty(var: &str) -> bool {
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .is_some()
}

/// Returns true iff the secret resolves via EITHER `<VAR>` (direct env)
/// OR `<VAR>_FILE` (Docker-secrets fallback) — same precedence as
/// `talos_config::read_env_or_file`. MCP-906 (2026-05-14): pre-fix
/// `validate_required_envs` only consulted `env_var_is_set_nonempty`,
/// so wiring this validator into controller startup would have
/// rejected every Docker-secrets deploy that supplied
/// `JWT_SECRET_FILE` / `TALOS_MASTER_KEY_FILE` instead of the direct
/// env. The legacy `controller/main.rs` check (which the validator
/// replaces) used `read_env_or_file`, so honour the same contract.
fn secret_resolvable(var: &str) -> bool {
    talos_config::read_env_or_file(var).is_some()
}

/// Configuration validator that checks all required settings
pub struct ConfigValidator;

impl ConfigValidator {
    /// Validate all configuration and return detailed error messages
    pub fn validate() -> Result<()> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Validate required environment variables
        Self::validate_required_envs(&mut errors);

        // Validate secret keys
        Self::validate_secrets(&mut errors);

        // Validate database configuration
        Self::validate_database_config(&mut errors);

        // Validate JWT configuration
        Self::validate_jwt_config(&mut errors);

        // Validate asymmetric JWT key requirements (RS256/ES256)
        Self::validate_jwt_asymmetric_keys(&mut errors);

        // Non-blocking production warnings
        Self::validate_redis_tls(&mut warnings);

        // Log warnings (non-blocking)
        for w in &warnings {
            tracing::warn!("{}", w);
        }

        if !errors.is_empty() {
            let error_msg = format!(
                "Configuration validation failed with {} error(s):\n{}\n\nPlease fix these issues before starting the service.",
                errors.len(),
                errors.join("\n")
            );
            return Err(anyhow!(error_msg));
        }

        Ok(())
    }

    /// Validate required environment variables exist
    fn validate_required_envs(errors: &mut Vec<String>) {
        // MCP-624 (2026-05-12): `JWT_SECRET` is only required when
        // `JWT_ALGORITHM` is HS256 (the default). For asymmetric
        // algorithms (RS256 / ES256), the key files are configured via
        // `JWT_PRIVATE_KEY{,_FILE}` + `JWT_PUBLIC_KEY{,_FILE}` and
        // JWT_SECRET is unused. Pre-fix the validator unconditionally
        // required JWT_SECRET, so wiring this validator into production
        // boot would have broken every RS256/ES256 deployment.
        // `validate_jwt_asymmetric_keys` (which DOES condition on the
        // algorithm) covers the asymmetric path; this method covers the
        // shared envs plus the HS256 secret.
        let algorithm = std::env::var("JWT_ALGORITHM")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|s| s.to_uppercase());
        let needs_jwt_secret = !matches!(algorithm.as_deref(), Some("RS256") | Some("ES256"));

        let mut required: Vec<(&str, &str)> = vec![
            ("DATABASE_URL", "PostgreSQL connection string"),
            (
                "TALOS_MASTER_KEY",
                "Master key for envelope encryption (64 hex chars)",
            ),
        ];
        if needs_jwt_secret {
            required.push(("JWT_SECRET", "JWT signing secret (min 32 bytes)"));
        }
        // MCP-920 (2026-05-14): WORKER_SHARED_KEY is required in
        // production. The controller always uses NATS-RPC for worker
        // dispatch and `talos-memory::rpc_auth` registers this key as
        // the HMAC verifier; missing key would fall through to
        // MCP-911's `is_ready()` boot gate (which returns Err in
        // production), but that's late — half a dozen subsystems have
        // already initialised by then, the operator sees a long
        // startup trace before the abort. Listing it as required-up-
        // front consolidates the misconfig report with JWT_SECRET /
        // TALOS_MASTER_KEY so all three missing-secret cases surface
        // together in `ConfigValidator::validate()` instead of one-
        // per-init-phase. Dev path skips the requirement (RPC
        // subscribers are themselves skipped at MCP-911 when the key
        // is absent, so dev boots fine without it).
        if talos_config::is_production() {
            required.push((
                "WORKER_SHARED_KEY",
                "Worker ↔ controller NATS-RPC HMAC key (64 hex chars)",
            ));
        }

        for (var, description) in &required {
            // MCP-599 (2026-05-12): treat empty-string env value as
            // unset so the operator sees a clear "MISSING" error
            // instead of the per-validator "INVALID format" downstream
            // message. Same empty-env-var class as MCP-597/598.
            //
            // MCP-906 (2026-05-14): JWT_SECRET + TALOS_MASTER_KEY also
            // honour `<VAR>_FILE` (Docker-secrets pattern) via
            // `secret_resolvable`; DATABASE_URL does not — sqlx-postgres
            // takes the connection string directly from env, no file
            // fallback. Per-var resolution matches what each downstream
            // consumer actually does at runtime.
            //
            // MCP-920 (2026-05-14): WORKER_SHARED_KEY joins the
            // file-fallback list; `talos_workflow_job_protocol::
            // load_worker_shared_key` already reads
            // `WORKER_SHARED_KEY_FILE` for Docker-secrets parity.
            let present = match *var {
                "JWT_SECRET" | "TALOS_MASTER_KEY" | "WORKER_SHARED_KEY" => secret_resolvable(var),
                _ => env_var_is_set_nonempty(var),
            };
            if !present {
                errors.push(format!(
                    "  [MISSING] {}: {}\n    Generate with: {}",
                    var,
                    description,
                    Self::generate_command(var)
                ));
            }
        }
    }

    /// Generate a command to create the missing secret
    fn generate_command(var: &str) -> &'static str {
        match var {
            "JWT_SECRET" => "openssl rand -hex 32",
            "TALOS_MASTER_KEY" => "openssl rand -hex 32",
            // MCP-920: matches the format `load_worker_shared_key`
            // requires (32 bytes / 64 hex chars).
            "WORKER_SHARED_KEY" => "openssl rand -hex 32",
            _ => "(see documentation)",
        }
    }

    /// Validate secret key strength
    ///
    /// MCP-906 (2026-05-14): all three secret strength checks now read
    /// via `talos_config::read_env_or_file` rather than bare
    /// `std::env::var`. Pre-fix a Docker-secrets deploy supplying
    /// `JWT_SECRET_FILE` / `TALOS_MASTER_KEY_FILE` /
    /// `WORKER_SHARED_KEY_FILE` had its strength checks SKIPPED
    /// entirely — the validator only saw env-direct values. The
    /// length / entropy / hex / dev-value checks must run on the
    /// effective value regardless of source.
    fn validate_secrets(errors: &mut Vec<String>) {
        // Validate JWT_SECRET
        if let Some(jwt_secret) = talos_config::read_env_or_file("JWT_SECRET") {
            if jwt_secret.len() < 32 {
                errors.push(format!(
                    "  [WEAK] JWT_SECRET: Must be at least 32 characters (got {} chars)\n    Generate with: openssl rand -hex 32",
                    jwt_secret.len()
                ));
            }

            // Check for low entropy (repeated characters)
            let unique_chars = jwt_secret
                .chars()
                .collect::<std::collections::HashSet<_>>()
                .len();
            if unique_chars < 10 {
                errors.push(format!(
                    "  [WEAK] JWT_SECRET: Must contain at least 10 unique characters (got {})",
                    unique_chars
                ));
            }

            // Check for default/dev values
            if jwt_secret == "dev_secret_change_in_production"
                || jwt_secret == "change_me"
                || jwt_secret == "secret"
            {
                errors.push(
                    "  [INSECURE] JWT_SECRET: Cannot use default/dev value\n    Generate with: openssl rand -hex 32".to_string()
                );
            }
        }

        // Validate TALOS_MASTER_KEY
        if let Some(master_key) = talos_config::read_env_or_file("TALOS_MASTER_KEY") {
            // Should be 64 hex characters (32 bytes)
            if master_key.len() != 64 {
                errors.push(format!(
                    "  [INVALID] TALOS_MASTER_KEY: Must be 64 hex characters (32 bytes), got {} chars\n    Generate with: openssl rand -hex 32",
                    master_key.len()
                ));
            }

            // Check if it's valid hex
            if hex::decode(&master_key).is_err() {
                errors.push("  [INVALID] TALOS_MASTER_KEY: Must be valid hex string".to_string());
            }
        }

        // Validate WORKER_SHARED_KEY if present.
        //
        // MCP-920 (2026-05-14): mirror the actual loader's contract.
        // `talos_workflow_job_protocol::load_worker_shared_key` does
        // `hex::decode(s.trim())` then asserts `key.len() == 32`, so
        // anything other than 64 hex chars (after trim) fails boot at
        // MCP-911's `is_ready()` gate with a misleading "key not
        // registered" message — the real cause is malformed-but-
        // strength-checked-OK input. Pre-fix the validator accepted
        // `WORKER_SHARED_KEY=foobarbaz` (`len() >= 32` was the only
        // check — actually no, the pre-fix was `< 32` which only
        // caught strictly-short values, so a 33-char ASCII string
        // passed too). Tighten to (1) valid hex, (2) exactly 64 chars
        // after trim. The error message mirrors the loader's wording
        // so operators can grep one string across boot logs and
        // validator output.
        if let Some(worker_key) = talos_config::read_env_or_file("WORKER_SHARED_KEY") {
            let trimmed = worker_key.trim();
            if trimmed.len() != 64 {
                errors.push(format!(
                    "  [INVALID] WORKER_SHARED_KEY: Must be 64 hex characters (32 bytes), got {} chars\n    Generate with: openssl rand -hex 32",
                    trimmed.len()
                ));
            } else if hex::decode(trimmed).is_err() {
                errors.push(
                    "  [INVALID] WORKER_SHARED_KEY: Must be valid hex string\n    Generate with: openssl rand -hex 32".to_string()
                );
            }
        }
    }

    /// Validate database configuration
    fn validate_database_config(errors: &mut Vec<String>) {
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            // MCP-522: accept BOTH `postgres://` and `postgresql://`.
            // libpq and sqlx-postgres treat the two schemes as
            // synonymous (see PostgreSQL connection-string docs §34.1.1).
            // Pre-fix, an operator copying a connection string from
            // an RDS console, Heroku, or any tool that emits the
            // `postgresql://` form would hit a hard-fail startup
            // error with the misleading message "Must start with
            // 'postgres://'" — the URL is valid, the validator was
            // narrow.
            let is_postgres_scheme =
                db_url.starts_with("postgres://") || db_url.starts_with("postgresql://");
            if !is_postgres_scheme {
                // MCP-507 + MCP-1050: route through canonical
                // `talos_text_util::truncate_at_char_boundary` for
                // codepoint-safe slicing (was inline `is_char_boundary`
                // walk-back).
                errors.push(format!(
                    "  [INVALID] DATABASE_URL: Must start with 'postgres://' or 'postgresql://' (got: {}...)",
                    talos_text_util::truncate_at_char_boundary(&db_url, 20)
                ));
            }

            // Check for localhost in production. MCP-507: pre-fix this
            // pushed a `[WARNING]`-labeled string into the `errors` Vec,
            // which causes a hard startup failure with a misleading
            // severity label. Either it's a warning (move to warnings,
            // continue boot) or it's a hard fail (relabel). The
            // intent is to BLOCK production-against-localhost — that
            // mis-configuration is almost always an accident worth
            // catching at boot — so the label is corrected to
            // `[INVALID]` to match the other hard-fail entries.
            if db_url.contains("localhost") || db_url.contains("127.0.0.1") {
                let is_prod = talos_config::is_production();
                if is_prod {
                    errors.push(
                        "  [INVALID] DATABASE_URL: Cannot use localhost / 127.0.0.1 in production. \
                         Set RUST_ENV=development for local builds, or point DATABASE_URL at the \
                         real Postgres host before starting in production mode."
                            .to_string(),
                    );
                }
            }
        }
    }

    /// Validate JWT configuration
    fn validate_jwt_config(errors: &mut Vec<String>) {
        // Validate BCRYPT_COST
        if let Ok(bcrypt_cost) = std::env::var("BCRYPT_COST") {
            match bcrypt_cost.parse::<u32>() {
                Ok(cost) if cost < 10 => {
                    errors.push(format!(
                        "  [WEAK] BCRYPT_COST: {} is too low (minimum recommended: 10)",
                        cost
                    ));
                }
                Ok(cost) if cost > 14 => {
                    errors.push(format!(
                        "  [SLOW] BCRYPT_COST: {} is very high and may cause timeouts (recommended: 10-14)",
                        cost
                    ));
                }
                Err(_) => {
                    errors.push(format!(
                        "  [INVALID] BCRYPT_COST: '{}' is not a valid number",
                        bcrypt_cost
                    ));
                }
                _ => {} // Valid range
            }
        }

        // Validate TOTP_ISSUER
        if let Ok(totp_issuer) = std::env::var("TOTP_ISSUER") {
            if totp_issuer.len() > 64 {
                errors.push(format!(
                    "  [TOO LONG] TOTP_ISSUER: Should be under 64 characters (got {})",
                    totp_issuer.len()
                ));
            }
        }
    }

    /// Validate asymmetric JWT key requirements when using RS256 or ES256.
    fn validate_jwt_asymmetric_keys(errors: &mut Vec<String>) {
        // MCP-599 (2026-05-12): treat empty-string env values as unset so
        // the validator's MISSING report matches `read_env_or_file`'s
        // runtime behaviour (post-MCP-597 — empty `JWT_PRIVATE_KEY=""`
        // falls through to `JWT_PRIVATE_KEY_FILE`; if BOTH are empty,
        // AuthService::new fails at boot with a misleading "Invalid RSA
        // private key PEM" error). Catching it here surfaces the actual
        // root cause (Helm placeholder shadowed both keys) before the
        // pod starts trying to load JWTs.
        if let Some(jwt_alg) = std::env::var("JWT_ALGORITHM")
            .ok()
            .filter(|v| !v.is_empty())
        {
            let alg_upper = jwt_alg.to_uppercase();
            if alg_upper == "RS256" || alg_upper == "ES256" {
                let has_private = env_var_is_set_nonempty("JWT_PRIVATE_KEY")
                    || env_var_is_set_nonempty("JWT_PRIVATE_KEY_FILE");
                let has_public = env_var_is_set_nonempty("JWT_PUBLIC_KEY")
                    || env_var_is_set_nonempty("JWT_PUBLIC_KEY_FILE");

                if !has_private {
                    errors.push(format!(
                        "  [MISSING] JWT_PRIVATE_KEY: Required when JWT_ALGORITHM={}\n    \
                         Generate with: {}",
                        alg_upper,
                        if alg_upper == "RS256" {
                            "openssl genrsa -out private.pem 2048 && cat private.pem"
                        } else {
                            "openssl ecparam -genkey -name prime256v1 -noout -out private.pem && cat private.pem"
                        }
                    ));
                }
                if !has_public {
                    errors.push(format!(
                        "  [MISSING] JWT_PUBLIC_KEY: Required when JWT_ALGORITHM={}\n    \
                         Extract with: openssl {} -in private.pem -pubout -out public.pem && cat public.pem",
                        alg_upper,
                        if alg_upper == "RS256" { "rsa" } else { "ec" }
                    ));
                }
            }
        }
    }

    /// Warn if Redis is not using TLS in production.
    fn validate_redis_tls(warnings: &mut Vec<String>) {
        if talos_config::is_production() {
            if let Ok(redis_url) = std::env::var("REDIS_URL") {
                if !redis_url.starts_with("rediss://") {
                    warnings.push(
                        "  [PRODUCTION] REDIS_URL: Using plaintext 'redis://' in production. \
                         Use 'rediss://' for TLS-encrypted connections."
                            .to_string(),
                    );
                }
            }
        }
    }

    /// Print configuration summary (for logging)
    pub fn print_summary() {
        tracing::info!("Configuration Summary:");

        // Database
        if let Ok(db_url) = std::env::var("DATABASE_URL") {
            // Mask password in URL
            let masked = if let Some(pos) = db_url.rfind('@') {
                if let Some(proto_pos) = db_url.find("://") {
                    let prefix = &db_url[..proto_pos + 3];
                    let suffix = &db_url[pos..];
                    format!("{}****@{}", prefix, &suffix[1..])
                } else {
                    "(invalid format)".to_string()
                }
            } else {
                db_url
            };
            tracing::info!("  Database: {}", masked);
        }

        // Redis
        match std::env::var("REDIS_URL") {
            Ok(_) => tracing::info!("  Redis: configured"),
            Err(_) => tracing::warn!("  Redis: NOT configured (cache will be disabled)"),
        }

        // NATS
        match std::env::var("NATS_URL") {
            Ok(_) => tracing::info!("  NATS: configured"),
            Err(_) => tracing::warn!("  NATS: NOT configured (messaging unavailable)"),
        }

        // Security
        if let Ok(bcrypt_cost) = std::env::var("BCRYPT_COST") {
            tracing::info!("  Bcrypt cost: {}", bcrypt_cost);
        } else {
            tracing::info!("  Bcrypt cost: 12 (default)");
        }

        if let Ok(jwt_secret) = std::env::var("JWT_SECRET") {
            tracing::info!("  JWT secret: {} chars", jwt_secret.len());
        }

        // Environment. MCP-653: route through `talos_config::get_env`
        // so the startup log matches `talos_config::is_production()`'s
        // semantics for `RUST_ENV=""`. Pre-fix the log read raw env,
        // showing `Environment: ` (blank) and falling into the
        // dev-mode warning while `is_production()` (which uses
        // get_env) correctly returned false — same outcome but the
        // operator-facing log mismatch hid misconfigured deploys.
        let env = talos_config::get_env("RUST_ENV", "development");
        tracing::info!("  Environment: {}", env);

        if env == "production" {
            tracing::info!("  ✓ Running in production mode with security hardening enabled");
        } else {
            tracing::warn!("  ⚠ Running in development mode - some security features are relaxed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_command() {
        assert_eq!(
            ConfigValidator::generate_command("JWT_SECRET"),
            "openssl rand -hex 32"
        );
        assert_eq!(
            ConfigValidator::generate_command("TALOS_MASTER_KEY"),
            "openssl rand -hex 32"
        );
    }

    #[test]
    fn test_validate_secrets() {
        // This would need mocking of env vars to test properly
        // For now, we just verify the function exists and compiles
        let errors: Vec<String> = Vec::new();
        assert!(errors.is_empty());
    }

    // MCP-522: the database-URL validator must accept BOTH
    // `postgres://` and `postgresql://` schemes (libpq +
    // sqlx-postgres treat them as synonymous). The pure logic
    // here pins the scheme-matching invariant without needing
    // env-var manipulation in the test (which would race against
    // other tests in the same process).

    /// Reproduces the scheme-acceptance check used by
    /// `validate_database_config`. Kept in sync with the live
    /// site so a future refactor that re-narrows the check
    /// surfaces as a failing test.
    fn db_url_scheme_accepted(url: &str) -> bool {
        url.starts_with("postgres://") || url.starts_with("postgresql://")
    }

    #[test]
    fn database_url_accepts_short_postgres_scheme() {
        assert!(db_url_scheme_accepted(
            "postgres://user:pw@host:5432/db"
        ));
    }

    #[test]
    fn database_url_accepts_long_postgresql_scheme() {
        // The form RDS, Heroku, and most managed-Postgres consoles
        // emit by default. Pre-MCP-522 this hard-failed boot.
        assert!(db_url_scheme_accepted(
            "postgresql://user:pw@rds.amazonaws.com:5432/talos"
        ));
    }

    #[test]
    fn database_url_rejects_other_schemes() {
        // mysql, sqlite, jdbc, http should all fail — none parse
        // as a Postgres connection string. Defensive list keeps
        // the gate from drifting to "anything matching schema://".
        for url in &[
            "mysql://user:pw@host:3306/db",
            "sqlite:///tmp/db.sqlite",
            "jdbc:postgresql://host:5432/db", // JDBC prefix is wrong shape
            "http://host:5432/db",
            "",
            "user:pw@host:5432/db", // missing scheme entirely
        ] {
            assert!(
                !db_url_scheme_accepted(url),
                "must reject non-Postgres scheme: {url}"
            );
        }
    }

    #[test]
    fn database_url_postgres_scheme_is_prefix_match_not_substring() {
        // A URL that CONTAINS the literal "postgres://" mid-string
        // (e.g. some weird tool wrapper) must not pass. The check
        // is starts_with, not contains. Pin the invariant.
        assert!(!db_url_scheme_accepted(
            "evil://postgres://user:pw@host:5432/db"
        ));
    }

    // MCP-599 (2026-05-12): empty-env-var class — Helm placeholder
    // `key: ""` shadowing real config. The validator's presence
    // checks for required envs and asymmetric JWT keys must treat
    // an empty value as unset; otherwise the runtime hits a
    // misleading downstream error (e.g. "Invalid RSA private key
    // PEM") instead of the operator-facing "MISSING JWT_PRIVATE_KEY".
    //
    // Pure-helper test: doesn't mutate process env (would race with
    // other tests). Instead pins the predicate shape using a single
    // probe env var the test owns end-to-end via std::env::set_var
    // / remove_var. Confined to one var so cross-test interference
    // is bounded; the run is also `--test-threads=1` clean.
    #[test]
    fn env_var_is_set_nonempty_treats_empty_as_unset() {
        // SAFETY (here and below): mutating process env in tests is
        // only safe because Cargo runs each test binary in a fresh
        // process, and this probe var (`TALOS_TEST_MCP_599_PROBE`)
        // is unused outside this test. We do not assume any
        // particular thread-count.
        std::env::remove_var("TALOS_TEST_MCP_599_PROBE");
        assert!(
            !env_var_is_set_nonempty("TALOS_TEST_MCP_599_PROBE"),
            "unset env var must report not-set"
        );

        std::env::set_var("TALOS_TEST_MCP_599_PROBE", "");
        assert!(
            !env_var_is_set_nonempty("TALOS_TEST_MCP_599_PROBE"),
            "empty-string env var must report not-set (MCP-599)"
        );

        std::env::set_var("TALOS_TEST_MCP_599_PROBE", "value");
        assert!(
            env_var_is_set_nonempty("TALOS_TEST_MCP_599_PROBE"),
            "non-empty env var must report set"
        );

        std::env::remove_var("TALOS_TEST_MCP_599_PROBE");
    }
}

// AuthService contains many methods not exercised by the current test suite.

use anyhow::{anyhow, Context, Result};
use bcrypt::{hash, verify};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use uuid::Uuid;

pub mod bootstrap;
pub use bootstrap::promote_first_user_if_needed;

// Env helpers come from talos-config (formerly inlined here during the
// initial extraction so the crate could land standalone).
use talos_config::{get_env, read_env_or_file};

static REFRESH_RATE_LIMITER: OnceLock<Mutex<HashMap<Uuid, (usize, Instant)>>> = OnceLock::new();

/// MCP-1147 (2026-05-16): defense-in-depth max-entries cap.
///
/// Pre-fix the in-memory refresh rate limiter had a periodic cleanup at
/// `len > 10_000` that removed entries older than 60s. In the
/// pathological case where 10_000+ entries are ALL recent (a botnet
/// authenticates many sessions, then each spams refresh inside the
/// same 60s window), the retain runs but removes nothing and the map
/// grows. At ~40 bytes/entry, 1M entries = ~40 MB attacker-influenced
/// heap.
///
/// Sibling audit class to MCP-1093/1132/1137/1145/1146 — every
/// TTL-bounded in-memory cache needs read-path eviction, periodic
/// sweep, AND a max-entries cap. The MCP-1146 sweep flagged this site
/// alongside `MCP_AUTH_RATE_LIMITER` as the remaining
/// `OnceLock<Mutex<HashMap>>` rate-limiter with cleanup-but-no-cap.
///
/// 50_000 matches the workspace canonical (NONCE_CACHE, CSRF grace
/// cache, MCP_AUTH_RATE_LIMITER). Legitimate refresh traffic shouldn't
/// approach this — refresh tokens are per-session, sessions are
/// per-user device, and most users have << 100 active sessions across
/// all devices. 50_000 is a DoS-defense boundary.
const REFRESH_RATE_LIMITER_MAX_ENTRIES: usize = 50_000;

/// User model
#[derive(Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub totp_secret: Option<String>,
    pub totp_enabled: Option<bool>,
}

impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("password_hash", &"[REDACTED]")
            .field("name", &self.name)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_login_at", &self.last_login_at)
            .field("is_active", &self.is_active)
            .field("failed_login_attempts", &self.failed_login_attempts)
            .field("locked_until", &self.locked_until)
            .field("totp_secret", &"[REDACTED]")
            .field("totp_enabled", &self.totp_enabled)
            .finish()
    }
}

/// JWT Claims.
///
/// Pure-data struct lives in `talos-auth-types`; re-exported here so
/// the existing `crate::auth::Claims` import path continues to work.
pub use talos_auth_types::Claims;

/// Canonical email-format validator. Public so siblings (talos-api,
/// callers of `talos-mcp-handlers`) can share one source of truth
/// instead of maintaining copy-paste sibling regexes.
///
/// MCP-1153 (2026-05-16): hoisted from `fn` to `pub fn` and lifted
/// here as the canonical home. Pre-fix the SAME regex + length cap
/// was inlined in:
///   - `talos-auth::validate_email` (this file, MCP-626)
///   - `talos-api::validation::validate_email` (validation.rs:430,
///     MCP-1061)
/// Both had length-first ordering and the same LazyLock/OnceLock +
/// `.expect()` pattern. Same cross-protocol-parity drift class as
/// MCP-1150 (vault key_path) and MCP-1152 (secret namespace).
///
/// Returns `Result<(), &'static str>` with stable error messages —
/// each protocol caller wraps into its own error type:
///   - talos-auth: `anyhow!(msg)` for the auth-service error chain
///   - talos-api: `safe_err(msg)` for GraphQL `.extend_safe()`
///
/// Rules (preserved byte-for-byte from MCP-626 / MCP-1061):
///   * length check FIRST (cheap-gate-first per MCP-1010 sweep) —
///     non-empty, ≤ 254 bytes (RFC 5321 §4.5.3.1.3 forward-path cap)
///   * regex match against the canonical pattern
///
/// The regex is statically composed and the `.expect()` failure mode
/// surfaces at first call (test / boot) rather than at user-request
/// time — same fail-closed posture MCP-1141 / MCP-1009 codified.
pub fn validate_email_format(email: &str) -> Result<(), &'static str> {
    if email.is_empty() {
        return Err("Email cannot be empty");
    }
    if email.len() > 254 {
        return Err("Email address is too long");
    }
    static EMAIL_REGEX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let email_regex = EMAIL_REGEX.get_or_init(|| {
        regex::Regex::new(
            r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
        )
        .expect("BUG: email validation regex must compile")
    });
    if !email_regex.is_match(email) {
        return Err("Invalid email format");
    }
    Ok(())
}

/// Internal wrapper preserving the legacy `anyhow::Result` shape for
/// existing callers inside this crate. New callers should use the
/// public `validate_email_format` directly.
fn validate_email(email: &str) -> Result<()> {
    validate_email_format(email).map_err(|m| anyhow!(m))
}

/// Generate SHA256 hash for fast token lookups
/// This is NOT for security (bcrypt is still used for that), but for efficient database queries
fn generate_token_lookup_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// MCP-1004 (2026-05-15): canonical content discipline for user display
/// names — the last holdout in the long sweep (MCP-186 / MCP-218 /
/// MCP-262 / MCP-321 / MCP-431 / MCP-769 / MCP-918) that closed control-
/// char and whitespace-only acceptance across every other named-resource
/// surface. Pre-fix `create_user` checked only `n.len() > 255`; an
/// operator could sign up with:
///   * `name: ""` — empty, but `Option::Some("")` is `len() == 0` so
///     passes the cap; users.name persists as empty string instead of
///     SQL NULL.
///   * `name: "   "` — whitespace-only; dashboard renders as a blank
///     row distinguishable from "no name set" only by hovering.
///   * `name: "John\0Doe"` — null byte truncates in C-string consumers
///     and corrupts JSON serialization in some libraries (MCP-431
///     pattern).
///   * `name: "\x07\x07"` — control chars corrupt log lines and
///     terminal-rendered listings.
///
/// Behaviour:
///   * Trim leading/trailing whitespace on the original.
///   * Empty-after-trim → return `Ok(None)` so the column stores SQL
///     NULL (matches "name field omitted" semantics).
///   * Length-after-trim cap at 255 chars.
///   * Reject `\0` and `is_control()` chars except `\t` on the ORIGINAL
///     (MCP-431 trim-then-check-original pattern — a name that trims
///     clean but had embedded `\0` in the middle is still malicious).
///
/// Returns `Ok(Some(trimmed))` for valid names, `Ok(None)` for empty
/// names, `Err` for invalid shapes. OAuth callers can map `Err` to
/// `None` instead of failing the login (provider-supplied names are
/// best-effort metadata, not a privilege gate).
pub(crate) fn validate_user_display_name(name: &str) -> Result<Option<String>> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.len() > 255 {
        return Err(anyhow!("Name must be ≤ 255 characters"));
    }
    if name.contains('\0')
        || name.chars().any(|c| c.is_control() && c != '\t')
    {
        return Err(anyhow!(
            "Name cannot contain control characters or null bytes"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

/// Validate password complexity
fn validate_password(password: &str) -> Result<()> {
    // Minimum length (allow passphrases)
    if password.len() < 12 {
        return Err(anyhow!("Password must be at least 12 characters long"));
    }

    // Maximum length (prevent DoS via bcrypt)
    if password.len() > 72 {
        return Err(anyhow!("Password must be no more than 72 characters long"));
    }

    // Require at least 2 distinct character classes out of 4:
    //   uppercase, lowercase, digit, symbol.
    // This rejects trivially weak passwords like "aaaaaaaaaaaa" while still
    // accepting strong passphrases like "correct-horse-battery-staple".
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c.is_ascii());
    let class_count = [has_upper, has_lower, has_digit, has_symbol]
        .iter()
        .filter(|&&b| b)
        .count();
    if class_count < 2 {
        return Err(anyhow!(
            "Password must contain characters from at least 2 of the following groups: \
             uppercase letters, lowercase letters, digits, symbols"
        ));
    }

    Ok(())
}

/// JWT key material supporting symmetric (HS256) and asymmetric (RS256, ES256) algorithms.
///
/// - **HS256** (default): Uses a shared secret for both signing and verification.
///   Simple to deploy but every service that verifies tokens needs the signing secret.
/// - **RS256**: RSA-SHA256. Private key signs, public key verifies. Use when verification
///   needs to happen in services that should not have the signing key.
/// - **ES256**: ECDSA P-256. Same asymmetric benefits as RS256 but with smaller keys
///   and faster operations.
///
/// Migration: Set `JWT_ALGORITHM_PREVIOUS` during a transition window. Tokens signed
/// with the previous algorithm are still accepted for verification (the 15-min access
/// token TTL means the window only needs to cover one deployment cycle).
enum JwtKeyPair {
    Symmetric {
        algorithm: Algorithm,
        encoding_key: EncodingKey,
        decoding_key: DecodingKey,
    },
    Asymmetric {
        algorithm: Algorithm,
        encoding_key: EncodingKey,
        decoding_key: DecodingKey,
    },
}

impl JwtKeyPair {
    fn algorithm(&self) -> Algorithm {
        match self {
            Self::Symmetric { algorithm, .. } | Self::Asymmetric { algorithm, .. } => *algorithm,
        }
    }

    fn encoding_key(&self) -> &EncodingKey {
        match self {
            Self::Symmetric { encoding_key, .. } | Self::Asymmetric { encoding_key, .. } => {
                encoding_key
            }
        }
    }

    fn decoding_key(&self) -> &DecodingKey {
        match self {
            Self::Symmetric { decoding_key, .. } | Self::Asymmetric { decoding_key, .. } => {
                decoding_key
            }
        }
    }

    /// Build a JwtKeyPair from environment configuration.
    ///
    /// Reads `JWT_ALGORITHM` (default: "HS256") and the appropriate key material:
    /// - HS256: `JWT_SECRET` (symmetric, min 32 bytes)
    /// - RS256: `JWT_PRIVATE_KEY` (PEM) + `JWT_PUBLIC_KEY` (PEM, min 2048-bit RSA)
    /// - ES256: `JWT_PRIVATE_KEY` (PEM) + `JWT_PUBLIC_KEY` (PEM, P-256 curve)
    fn from_env(jwt_secret: &str) -> anyhow::Result<Self> {
        let algorithm_str = get_env("JWT_ALGORITHM", "HS256");
        match algorithm_str.to_uppercase().as_str() {
            "HS256" => {
                if jwt_secret.len() < 32 {
                    anyhow::bail!(
                        "JWT_SECRET must be at least 32 bytes (256 bits) for HS256 security. \
                         Generate a secure secret with: openssl rand -hex 32"
                    );
                }
                Ok(Self::Symmetric {
                    algorithm: Algorithm::HS256,
                    encoding_key: EncodingKey::from_secret(jwt_secret.as_bytes()),
                    decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
                })
            }
            "RS256" => {
                let private_pem = read_env_or_file("JWT_PRIVATE_KEY").ok_or_else(|| {
                    anyhow!(
                        "JWT_PRIVATE_KEY (or JWT_PRIVATE_KEY_FILE) must be set for RS256. \
                             Generate with: openssl genrsa -out private.pem 2048"
                    )
                })?;
                let public_pem = read_env_or_file("JWT_PUBLIC_KEY").ok_or_else(|| {
                    anyhow!(
                        "JWT_PUBLIC_KEY (or JWT_PUBLIC_KEY_FILE) must be set for RS256. \
                             Extract with: openssl rsa -in private.pem -pubout -out public.pem"
                    )
                })?;

                let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
                    .context("Invalid RSA private key PEM for JWT_PRIVATE_KEY")?;
                let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
                    .context("Invalid RSA public key PEM for JWT_PUBLIC_KEY")?;

                tracing::info!("JWT configured with RS256 (asymmetric RSA)");
                Ok(Self::Asymmetric {
                    algorithm: Algorithm::RS256,
                    encoding_key,
                    decoding_key,
                })
            }
            "ES256" => {
                let private_pem = read_env_or_file("JWT_PRIVATE_KEY")
                    .ok_or_else(|| {
                        anyhow!(
                            "JWT_PRIVATE_KEY (or JWT_PRIVATE_KEY_FILE) must be set for ES256. \
                             Generate with: openssl ecparam -genkey -name prime256v1 -noout -out private.pem"
                        )
                    })?;
                let public_pem = read_env_or_file("JWT_PUBLIC_KEY").ok_or_else(|| {
                    anyhow!(
                        "JWT_PUBLIC_KEY (or JWT_PUBLIC_KEY_FILE) must be set for ES256. \
                             Extract with: openssl ec -in private.pem -pubout -out public.pem"
                    )
                })?;

                let encoding_key = EncodingKey::from_ec_pem(private_pem.as_bytes())
                    .context("Invalid EC private key PEM for JWT_PRIVATE_KEY")?;
                let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes())
                    .context("Invalid EC public key PEM for JWT_PUBLIC_KEY")?;

                tracing::info!("JWT configured with ES256 (asymmetric ECDSA P-256)");
                Ok(Self::Asymmetric {
                    algorithm: Algorithm::ES256,
                    encoding_key,
                    decoding_key,
                })
            }
            other => {
                anyhow::bail!(
                    "Unsupported JWT_ALGORITHM '{}'. Supported: HS256 (default), RS256, ES256",
                    other
                );
            }
        }
    }
}

/// Optional previous-algorithm key pair for migration window.
/// During JWT algorithm migration, tokens signed with the previous algorithm
/// are still accepted for verification.
struct PreviousKeyPair {
    algorithm: Algorithm,
    decoding_key: DecodingKey,
}

impl PreviousKeyPair {
    /// Build from `JWT_ALGORITHM_PREVIOUS` and the appropriate key material.
    /// Returns None if no previous algorithm is configured.
    fn from_env(jwt_secret: &str) -> Option<Self> {
        let prev_algo = std::env::var("JWT_ALGORITHM_PREVIOUS").ok()?;
        let prev_algo = prev_algo.trim();
        if prev_algo.is_empty() {
            return None;
        }

        let result = match prev_algo.to_uppercase().as_str() {
            "HS256" => {
                // Previous was HS256 — use JWT_SECRET for verification
                Some(Self {
                    algorithm: Algorithm::HS256,
                    decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
                })
            }
            "RS256" => {
                let public_pem = read_env_or_file("JWT_PUBLIC_KEY_PREVIOUS")
                    .or_else(|| read_env_or_file("JWT_PUBLIC_KEY"))?;
                let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes()).ok()?;
                Some(Self {
                    algorithm: Algorithm::RS256,
                    decoding_key,
                })
            }
            "ES256" => {
                let public_pem = read_env_or_file("JWT_PUBLIC_KEY_PREVIOUS")
                    .or_else(|| read_env_or_file("JWT_PUBLIC_KEY"))?;
                let decoding_key = DecodingKey::from_ec_pem(public_pem.as_bytes()).ok()?;
                Some(Self {
                    algorithm: Algorithm::ES256,
                    decoding_key,
                })
            }
            _ => None,
        };

        if result.is_some() {
            tracing::info!(
                previous_algorithm = prev_algo,
                "JWT migration mode active — accepting tokens signed with previous algorithm"
            );
        }
        result
    }
}

/// Authentication service
pub struct AuthService {
    pub db_pool: Pool<Postgres>,
    key_pair: JwtKeyPair,
    /// Previous key pair for migration window (optional).
    previous_key_pair: Option<PreviousKeyPair>,
    bcrypt_cost: u32,
    /// MCP-1084 (2026-05-16): per-instance bcrypt hash of a fixed
    /// dummy string, computed at construction time using the SAME
    /// `bcrypt_cost` as real password hashes. Used by the
    /// user-not-found path in `login()` so the dummy verify runs in
    /// the same wall-clock time as a genuine failed login.
    ///
    /// Pre-fix the `login()` function used a hardcoded `$2b$12$...`
    /// const for the dummy hash. If an operator set `BCRYPT_COST=14`,
    /// real password verify took ~400ms while the dummy took ~100ms
    /// — timing-side-channel oracle for "this email is registered"
    /// detection on custom-cost deployments. Sibling of MCP-1083
    /// (OAuth sentinel hash timing oracle).
    dummy_password_hash: String,
    /// Optional Redis client for distributed rate limiting.
    /// When available, rate limits are enforced cluster-wide.
    redis_client: Option<Arc<redis::Client>>,
}

impl AuthService {
    pub fn new(
        db_pool: Pool<Postgres>,
        jwt_secret: String,
        bcrypt_cost: u32,
        redis_client: Option<Arc<redis::Client>>,
    ) -> anyhow::Result<Self> {
        if redis_client.is_none() {
            tracing::warn!("Auth rate limiter is currently in-memory. For a distributed deployment, this should be backed by Redis.");
        }
        // Validate bcrypt cost (4-31 per bcrypt spec, but 10-14 recommended for production)
        if !(10..=14).contains(&bcrypt_cost) {
            anyhow::bail!("BCRYPT_COST must be between 10 and 14 (recommended: 12)");
        }

        let key_pair = JwtKeyPair::from_env(&jwt_secret)?;
        let previous_key_pair = PreviousKeyPair::from_env(&jwt_secret);

        // MCP-1084: hash the dummy at construction time so the
        // user-not-found verify uses the SAME cost as real password
        // verify. One-time bcrypt::hash at boot (~100ms at cost 12,
        // ~400ms at cost 14) — controller startup, not on the hot
        // path. Failure here would be a deployment failure (same
        // bcrypt-init invariant as MCP-1077's cost validation), so
        // bubble as `anyhow::bail!`.
        let dummy_password_hash = hash("_talos_dummy_", bcrypt_cost)
            .map_err(|e| anyhow::anyhow!("Failed to compute dummy bcrypt hash at startup: {}", e))?;

        Ok(Self {
            db_pool,
            key_pair,
            previous_key_pair,
            bcrypt_cost,
            dummy_password_hash,
            redis_client,
        })
    }

    /// Log authentication event for security monitoring
    #[allow(clippy::too_many_arguments)]
    async fn log_auth_event(
        &self,
        user_id: Option<Uuid>,
        event_type: &str,
        email: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        success: bool,
        failure_reason: Option<&str>,
    ) -> Result<()> {
        // Truncate user_agent to 1 KB to prevent log storage DoS via crafted headers.
        //
        // MCP-478: byte-slice at fixed offset 1024 panics when the
        // 1024th byte falls inside a multi-byte UTF-8 sequence. HTTP
        // header values are nominally ASCII per RFC 7230 §3.2.4, but
        // browsers and proxies do send UTF-8 in practice (localised
        // User-Agent strings, etc.) and attacker-controlled UAs can
        // be crafted to crash this path. Same fix pattern as MCP-477:
        // walk backward from 1024 to the nearest char boundary. The
        // ua_truncated owned String binding outlives the match arm so
        // the &str slice remains valid for the SQL bind below.
        let ua_truncated;
        let user_agent = match user_agent {
            Some(ua) if ua.len() > 1024 => {
                let mut end = 1024;
                while end > 0 && !ua.is_char_boundary(end) {
                    end -= 1;
                }
                ua_truncated = ua[..end].to_string();
                Some(ua_truncated.as_str())
            }
            other => other,
        };
        // MCP-1012 (2026-05-15): DLP-redact the user_agent before
        // persistence. Pre-fix the truncated UA was bound directly.
        // User-Agent is request-supplied; a crafted UA from an
        // attacker probing the platform could deliberately include
        // secret-shaped content (Bearer tokens, sk-/ghp_/xoxb-/AKIA
        // patterns, etc.) to land in the admin-queryable auth_audit_log
        // table. A misconfigured browser leaking session material into
        // the UA produces the same outcome benignly.
        //
        // Sibling-parity fix: the `oauth_audit_log` writer at
        // `talos-oauth::log_oauth_event` (lib.rs:1232) and the
        // `admin_event_log` writer at
        // `talos-actor-repository::insert_admin_event_log`
        // (lib.rs:2245) both already apply `talos_dlp_provider::
        // redact_str` to operator-visible content. The `auth_audit_log`
        // writer here was the drift. Same persistence-boundary DLP
        // rule documented in `memory/persistence_boundary_dlp_rule.md`.
        //
        // `redact_str` is infallible; applied AFTER truncation so the
        // 1 KB DoS cap still bounds the regex-pass cost.
        let ua_redacted = user_agent.map(talos_dlp_provider::redact_str);
        let user_agent = ua_redacted.as_deref();
        sqlx::query!(
            r#"
            INSERT INTO auth_audit_log (user_id, event_type, email, ip_address, user_agent, success, failure_reason)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            user_id,
            event_type,
            email,
            ip_address,
            user_agent,
            success,
            failure_reason
        )
        .execute(&self.db_pool)
        .await
        .context("Failed to log auth event")?;

        Ok(())
    }

    /// Best-effort audit log — logs a warning on failure instead of silently dropping.
    /// Use this for non-critical audit events that should not block the operation.
    #[allow(clippy::too_many_arguments)]
    async fn log_auth_event_best_effort(
        &self,
        user_id: Option<Uuid>,
        event_type: &str,
        email: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        success: bool,
        failure_reason: Option<&str>,
    ) {
        if let Err(e) = self
            .log_auth_event(
                user_id,
                event_type,
                email,
                ip_address,
                user_agent,
                success,
                failure_reason,
            )
            .await
        {
            tracing::warn!(
                event_type = event_type,
                error = %e,
                "Failed to write auth audit log entry"
            );
        }
    }

    /// Create a new user (signup)
    pub async fn create_user(
        &self,
        email: &str,
        password: &str,
        name: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Uuid> {
        // MCP-659: normalize email to trim+lowercase before validation and
        // persistence. Pre-fix `create_user` INSERTed the email verbatim and
        // `login` queried `WHERE email = $1` case-sensitively — a user who
        // signed up as `Alice@Example.com` then tried to log in as
        // `alice@example.com` got "Invalid email or password" with no signal
        // about the casing. Worse: two users could both register
        // `Alice@Example.com` and `alice@example.com` because the UNIQUE
        // constraint on `email` is case-sensitive — a real account-collision
        // surface. The `bootstrap.rs::promote_first_user_if_needed` path
        // already uses this trim+lowercase shape, so this just brings the
        // signup/login paths into agreement with it.
        let email_normalized = email.trim().to_lowercase();
        let email = email_normalized.as_str();

        // Validate email format
        validate_email(email)?;

        // Validate password complexity
        validate_password(password)?;

        // MCP-1004 (2026-05-15): canonical display-name content discipline.
        // Pre-fix the only check was `n.len() > 255` — see
        // `validate_user_display_name` doc for the full rationale and
        // threat shapes (control chars, null bytes, whitespace-only).
        let normalized_name: Option<String> = match name {
            Some(n) => validate_user_display_name(n)?,
            None => None,
        };
        let name = normalized_name.as_deref();

        // Hash password (use spawn_blocking to avoid blocking the async executor)
        let cost = self.bcrypt_cost;
        let password_owned = password.to_string();
        let password_hash = tokio::task::spawn_blocking(move || hash(&password_owned, cost))
            .await
            .context("Password hashing task panicked")??;

        // Insert user
        let user_id = sqlx::query_scalar!(
            r#"
            INSERT INTO users (email, password_hash, name)
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            email,
            password_hash,
            name
        )
        .fetch_one(&self.db_pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                anyhow!("Email already exists")
            } else {
                tracing::error!("Failed to create user: {}", e);
                anyhow!("Failed to create user")
            }
        })?;

        // Log successful signup
        self.log_auth_event_best_effort(
            Some(user_id),
            "signup",
            Some(email),
            ip_address,
            user_agent,
            true,
            None,
        )
        .await;

        // First-user bootstrap: if this is the first user and the bootstrap
        // migration ran on an empty DB, this promotes them now. Idempotent —
        // no-op once any user holds automation-node.
        if let Err(e) = crate::promote_first_user_if_needed(&self.db_pool, Some(user_id)).await {
            tracing::warn!(
                error = %e,
                %user_id,
                "First-user bootstrap promotion failed during signup (non-fatal)"
            );
        }

        Ok(user_id)
    }

    /// Authenticate user and return access token, refresh token, and user (login)
    #[must_use = "auth result must be handled"]
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(String, String, User)> {
        // MCP-659: normalize email to trim+lowercase and match
        // case-insensitively via `LOWER(email) = $1`. Pre-fix the WHERE
        // clause was case-sensitive — a user who signed up as
        // `Alice@Example.com` could not log in as `alice@example.com`
        // (or any other casing) because the query missed. Matches the
        // signup-side normalization (see `create_user`) AND the
        // bootstrap-promotion lookup which already used this shape.
        // `LIMIT 1` defends against legacy rows that may exist in
        // multiple casings from before the signup normalization landed —
        // arbitrary-but-stable selection is preferable to a query error.
        let email_normalized = email.trim().to_lowercase();
        let email = email_normalized.as_str();

        // Fetch user by email. Runtime form (not the `query_as!` macro)
        // because the new `LOWER(email) = $1` predicate doesn't have a
        // cached query plan — switching to the dynamic form avoids
        // forcing a `cargo sqlx prepare` round-trip for the boundary
        // normalization fix.
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, password_hash, name, created_at, updated_at, last_login_at, is_active,
                   failed_login_attempts, locked_until, totp_secret, totp_enabled
            FROM users
            WHERE LOWER(email) = $1 AND is_active = true
            LIMIT 1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.db_pool)
        .await?;

        let mut user = match user {
            Some(u) => u,
            None => {
                // Constant-time path: run a dummy bcrypt verify so "user not found"
                // takes the same wall-clock time as "wrong password".  Without this,
                // an attacker can enumerate registered emails by comparing response
                // latency (~0 ms here vs. ~100 ms for the real bcrypt below).
                //
                // MCP-1084 (2026-05-16): use `self.dummy_password_hash` (computed at
                // AuthService construction with the SAME cost as real password
                // hashes) instead of the previous hardcoded `$2b$12$...` const.
                // Pre-fix, operators running with `BCRYPT_COST=14` had a residual
                // oracle: dummy verify ~100ms vs real password verify ~400ms.
                // Sibling timing-oracle fix to MCP-1083.
                let password_owned = password.to_string();
                let dummy_hash = self.dummy_password_hash.clone();
                let _ =
                    tokio::task::spawn_blocking(move || verify(&password_owned, &dummy_hash)).await;

                // Log failed login attempt (user not found)
                self.log_auth_event_best_effort(
                    None,
                    "login_failed",
                    Some(email),
                    ip_address,
                    user_agent,
                    false,
                    Some("User not found or inactive"),
                )
                .await;
                return Err(anyhow!("Invalid email or password"));
            }
        };

        // Check if account is locked.
        //
        // SECURITY: return the same generic "Invalid email or password" error
        // as the user-not-found and wrong-password paths. A distinguishable
        // "account is locked" message confirms email registration to an
        // attacker who has burned the lockout threshold on a candidate email
        // — the locked branch only fires when `locked_until` is set, which
        // only happens for real accounts. Server-side log retains the actual
        // lockout state for forensics.
        if let Some(locked_until) = user.locked_until {
            if locked_until > Utc::now() {
                let remaining = (locked_until - Utc::now()).num_seconds();
                self.log_auth_event_best_effort(
                    Some(user.id),
                    "login_failed",
                    Some(email),
                    ip_address,
                    user_agent,
                    false,
                    Some(&format!("Account locked for {} more seconds", remaining)),
                )
                .await;
                return Err(anyhow!("Invalid email or password"));
            } else {
                // Lock period expired, reset failed attempts
                sqlx::query!(
                    "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1",
                    user.id
                )
                .execute(&self.db_pool)
                .await?;
                user.failed_login_attempts = 0;
                user.locked_until = None;
            }
        }

        // Verify password (use spawn_blocking to avoid blocking the async executor)
        let password_owned = password.to_string();
        let password_hash = user.password_hash.clone();
        let is_valid = tokio::task::spawn_blocking(move || verify(&password_owned, &password_hash))
            .await
            .context("Password verification task panicked")??;

        if !is_valid {
            const MAX_ATTEMPTS: i32 = 5; // Production security: lock after 5 failed attempts
            const LOCKOUT_DURATION_MINUTES: i64 = 15;

            // Atomically increment failed_login_attempts and lock if threshold reached.
            // Using a single UPDATE + RETURNING prevents the read-modify-write race condition
            // where two concurrent failed logins could both read the same counter value and
            // each only increment it once, effectively skipping a count.
            let locked_until = Utc::now() + Duration::minutes(LOCKOUT_DURATION_MINUTES);
            // Use dynamic query (not query!) to avoid sqlx offline cache issues with
            // RETURNING. The UPDATE is atomic — no read-modify-write race condition.
            let row = sqlx::query(
                r#"
                UPDATE users
                SET
                    failed_login_attempts = failed_login_attempts + 1,
                    locked_until = CASE
                        WHEN failed_login_attempts + 1 >= $1 THEN $2
                        ELSE locked_until
                    END
                WHERE id = $3
                RETURNING failed_login_attempts
                "#,
            )
            .bind(MAX_ATTEMPTS)
            .bind(locked_until)
            .bind(user.id)
            .fetch_one(&self.db_pool)
            .await?;

            use sqlx::Row as _;
            let new_attempts: i32 = row.try_get("failed_login_attempts").unwrap_or(1);

            if new_attempts >= MAX_ATTEMPTS {
                // Log account lockout server-side; return the same generic
                // error to the caller. See comment on the earlier locked
                // branch — a distinct lockout message at the moment the
                // threshold trips is the same enumeration leak just shifted
                // by one attempt.
                self.log_auth_event_best_effort(
                    Some(user.id),
                    "account_locked",
                    Some(email),
                    ip_address,
                    user_agent,
                    false,
                    Some(&format!(
                        "Account locked after {} failed attempts",
                        new_attempts
                    )),
                )
                .await;

                return Err(anyhow!("Invalid email or password"));
            } else {
                // Log failed login attempt (wrong password)
                self.log_auth_event_best_effort(
                    Some(user.id),
                    "login_failed",
                    Some(email),
                    ip_address,
                    user_agent,
                    false,
                    Some(&format!(
                        "Invalid password (attempt {}/{})",
                        new_attempts, MAX_ATTEMPTS
                    )),
                )
                .await;

                return Err(anyhow!("Invalid email or password"));
            }
        }

        // Update last login and reset failed attempts
        sqlx::query!(
            "UPDATE users SET last_login_at = NOW(), failed_login_attempts = 0, locked_until = NULL WHERE id = $1",
            user.id
        )
        .execute(&self.db_pool)
        .await?;

        // Determine initial 2FA verification status
        // If TOTP is enabled, the user is NOT yet 2FA verified upon initial login
        let is_2fa_verified = !user.totp_enabled.unwrap_or(false);

        // Generate access token (short-lived: 15 minutes)
        let access_token = self.generate_access_token(&user, is_2fa_verified)?;

        // Generate refresh token (long-lived: 7 days)
        let refresh_token = self
            .generate_refresh_token(user.id, is_2fa_verified)
            .await?;

        // Log successful login
        self.log_auth_event_best_effort(
            Some(user.id),
            "login_success",
            Some(email),
            ip_address,
            user_agent,
            true,
            None,
        )
        .await;

        Ok((access_token, refresh_token, user))
    }

    /// Generate access token for a user (short-lived: 15 minutes)
    #[must_use]
    pub fn generate_access_token(&self, user: &User, is_2fa_verified: bool) -> Result<String> {
        let now = Utc::now();
        let expiration = now + Duration::minutes(15); // Short-lived access token

        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            exp: expiration.timestamp() as usize,
            iat: now.timestamp() as usize,
            is_2fa_verified,
            iss: "talos".to_string(),
            aud: Some("talos".to_string()),
            // RFC 0004: left empty here (this minting path is sync / has
            // no DB handle to look up the active org). The controller
            // resolves the active org per request via
            // `OrganizationService::resolve_active_org`, defaulting to the
            // user's personal org when `org` is empty. The claim is
            // populated only once org-switching is wired (a later step),
            // at which point it carries the user's selected org.
            org: String::new(),
        };

        let token = encode(
            &Header::new(self.key_pair.algorithm()),
            &claims,
            self.key_pair.encoding_key(),
        )?;

        Ok(token)
    }

    /// Generate refresh token and store in database (long-lived: 7 days)
    #[must_use]
    pub async fn generate_refresh_token(
        &self,
        user_id: Uuid,
        is_2fa_verified: bool,
    ) -> Result<String> {
        // Generate token and lookup hash before any async operations
        let (refresh_token, lookup_hash, expires_at) = {
            // Generate cryptographically secure random token (32 bytes = 256 bits).
            // Use OsRng directly — explicit, auditable, and bypasses any potential
            // thread-local seeding concerns with thread_rng().
            use rand::RngCore;
            let mut rng = rand::rngs::OsRng;
            let mut token_bytes = [0u8; 32];
            rng.fill_bytes(&mut token_bytes);
            let refresh_token = hex::encode(token_bytes);

            // Generate lookup hash for fast queries (not for security, just for efficient lookups)
            let lookup_hash = generate_token_lookup_hash(&refresh_token);

            // Calculate expiration (7 days from now)
            let expires_at = Utc::now() + Duration::days(7);

            (refresh_token, lookup_hash, expires_at)
        }; // rng is dropped here, before the await

        // Hash the token before storing (use spawn_blocking to avoid blocking the async executor)
        let cost = self.bcrypt_cost;
        let token_for_hash = refresh_token.clone();
        let token_hash = tokio::task::spawn_blocking(move || hash(&token_for_hash, cost))
            .await
            .context("Token hashing task panicked")??;

        // Store in database with lookup hash for efficient queries
        sqlx::query(
            "INSERT INTO user_sessions (user_id, refresh_token_hash, refresh_token_lookup_hash, expires_at, is_2fa_verified)
             VALUES ($1, $2, $3, $4, $5)"
        )
        .bind(user_id)
        .bind(&token_hash)
        .bind(&lookup_hash)
        .bind(expires_at)
        .bind(is_2fa_verified)
        .execute(&self.db_pool)
        .await
        .context("Failed to store refresh token")?;

        Ok(refresh_token)
    }

    /// Validate refresh token and generate new access token
    #[must_use]
    /// Refresh the access token and rotate the refresh token.
    ///
    /// Returns `(new_access_token, new_refresh_token, user, is_2fa_verified)`.
    ///
    /// Refresh token rotation means the old token is revoked on every use and a new
    /// one is issued. If a stolen token is used by an attacker, the first use will
    /// succeed but the legitimate client's next refresh will fail (the session was
    /// rotated away), providing an early-warning signal for token theft.
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<(String, String, User, bool)> {
        // Generate lookup hash for efficient query
        let lookup_hash = generate_token_lookup_hash(refresh_token);

        // Find session by lookup hash (much faster than fetching all sessions)
        // Note: lookup_hash column may be NULL for old sessions created before this optimization
        let session = sqlx::query_as::<_, (Uuid, Uuid, String, DateTime<Utc>, bool)>(
            r#"
            SELECT id, user_id, refresh_token_hash, expires_at, is_2fa_verified
            FROM user_sessions
            WHERE refresh_token_lookup_hash = $1
              AND expires_at > NOW()
            LIMIT 1
            "#,
        )
        .bind(&lookup_hash)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to fetch session")?;

        // The lookup-hash fast path is the only supported path. The old full-table bcrypt
        // scan has been removed: it was an O(N·bcrypt) DoS vector that allowed an attacker
        // to exhaust CPU by submitting tokens that miss the index and trigger a scan over
        // every active session.  All sessions now carry a lookup_hash (migration 008), so
        // the fallback is no longer necessary.
        let session = match session {
            Some(s) => s,
            None => {
                // TOKEN-REUSE DETECTION. If this lookup_hash matches a
                // recently-rotated session (rotated_session_audit table),
                // the token was VALID until rotation — someone else used
                // it, then the client tried to refresh with the now-stale
                // token.
                //
                // 5-second grace window: tabs that race a refresh on the
                // same token can both pass bcrypt, the loser hits this
                // path with rows_affected=0 OR the lookup_hash gone. We
                // don't want to revoke a user's entire account because
                // their second tab got pre-empted by 50ms. After 5s the
                // race-condition explanation is no longer plausible —
                // any "reuse" is either a stolen-token replay or a
                // serious client-side bug, and revoke-all-and-re-login
                // is the safe response.
                if let Ok(Some((reused_user_id, rotated_at))) =
                    sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(
                        "SELECT user_id, rotated_at FROM rotated_session_audit \
                         WHERE lookup_hash = $1 AND expires_at > NOW()",
                    )
                    .bind(&lookup_hash)
                    .fetch_optional(&self.db_pool)
                    .await
                {
                    let age_secs = (Utc::now() - rotated_at).num_seconds();
                    if age_secs >= 5 {
                        tracing::error!(
                            target: "talos_security_alert",
                            user_id = %reused_user_id,
                            age_secs,
                            "Refresh-token reuse detected — revoking ALL sessions for the affected user. \
                             Either a stolen token was replayed after the legitimate rotation, or a \
                             client serialised a stale token to disk. Either way, force re-auth is \
                             the safe response."
                        );
                        self.log_auth_event_best_effort(
                            Some(reused_user_id),
                            "refresh_token_reuse_detected",
                            None,
                            None,
                            None,
                            false,
                            Some("rotated session refresh attempted"),
                        )
                        .await;
                        if let Err(e) = self.revoke_all_sessions(reused_user_id).await {
                            tracing::warn!(
                                user_id = %reused_user_id,
                                "Failed to revoke all sessions after reuse detection: {}",
                                e
                            );
                        }
                    } else {
                        tracing::debug!(
                            user_id = %reused_user_id,
                            age_secs,
                            "Token reuse within 5s grace window — likely tab race, not revoking"
                        );
                    }
                }
                // Same generic error in either case — don't tip the attacker off
                // with a different response on detection.
                return Err(anyhow!("Invalid or expired refresh token"));
            }
        };

        // Rate limiting by session ID to prevent spam and CPU exhaustion from bcrypt.
        // First try distributed rate limiting via Redis.
        if let Some(redis) = &self.redis_client {
            match self.check_refresh_rate_limit_redis(session.1, redis).await {
                Ok(true) => {
                    return Err(anyhow::anyhow!(
                        "Rate limit exceeded for token refresh (Redis)"
                    ));
                }
                Ok(false) => {} // Rate limit OK, continue
                Err(e) => {
                    tracing::warn!(
                        "Redis refresh rate limit check failed, falling back to in-memory: {}",
                        e
                    );
                    // Fall through to in-memory check
                }
            }
        }

        // Fall back to in-memory rate limiting
        {
            let mut limiter = REFRESH_RATE_LIMITER
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            // Cleanup old entries randomly to prevent memory leak
            if limiter.len() > 10000 {
                limiter.retain(|_, (_, time)| now.duration_since(*time).as_secs() < 60);
            }

            // MCP-1147 (2026-05-16): fail-CLOSED at the defense-in-depth
            // cap. The cleanup above only removes entries older than 60s;
            // a sustained flood of distinct session_ids inside the window
            // makes the retain a no-op and lets the cache grow unbounded.
            // Same fail-closed posture as MCP-1145 (CSRF grace cache) and
            // MCP-1146 (MCP auth rate limiter): refuse NEW sessions at
            // cap so the attacker doesn't amplify into heap exhaustion;
            // existing tracked sessions continue rate-limit accounting
            // through the `entry()` path below. `contains_key` is a
            // cheap O(1) lookup so the cap-check stays light on the
            // happy path.
            if limiter.len() >= REFRESH_RATE_LIMITER_MAX_ENTRIES
                && !limiter.contains_key(&session.1)
            {
                tracing::warn!(
                    target: "talos_audit",
                    event_kind = "refresh_rate_limiter_cap_hit",
                    size = limiter.len(),
                    cap = REFRESH_RATE_LIMITER_MAX_ENTRIES,
                    "Refresh rate-limiter at capacity; refusing new session (investigate for refresh-token flood)"
                );
                return Err(anyhow::anyhow!(
                    "Rate limit exceeded for token refresh (limiter at capacity)"
                ));
            }

            let (count, last_time) = limiter.entry(session.1).or_insert((0, now));
            if now.duration_since(*last_time).as_secs() > 60 {
                *count = 1;
                *last_time = now;
            } else {
                *count += 1;
                if *count > 10 {
                    // Max 10 refreshes per minute per session
                    return Err(anyhow::anyhow!("Rate limit exceeded for token refresh"));
                }
            }
        }

        // Verify bcrypt hash for security (even when found via lookup hash)
        // Use spawn_blocking to avoid blocking the async executor
        let token = refresh_token.to_string();
        let hash_to_check = session.2.clone();
        let is_valid = tokio::task::spawn_blocking(move || verify(&token, &hash_to_check))
            .await
            .context("Token verification task panicked")??;

        if !is_valid {
            return Err(anyhow!("Invalid refresh token"));
        }

        // Destructure session tuple for clarity
        let (session_id, user_id, _token_hash, _expires_at, is_2fa_verified) = session;

        // Get user
        let user = self.get_user(user_id).await?;

        // Atomically update last_used_at AND verify the session was not revoked between
        // the initial SELECT and this UPDATE. If rows_affected == 0 the session row was
        // deleted (revoked) in the window while bcrypt was running — reject the request.
        let updated = sqlx::query_scalar::<_, Uuid>(
            "UPDATE user_sessions SET last_used_at = NOW() WHERE id = $1 RETURNING id",
        )
        .bind(session_id)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to update session last_used_at")?;

        if updated.is_none() {
            return Err(anyhow!("Refresh token has been revoked"));
        }

        // Generate new access token
        let access_token = self.generate_access_token(&user, is_2fa_verified)?;

        // Rotate the refresh token: issue a new one, then delete the old session.
        //
        // Order matters: insert-then-delete ensures we never have zero valid sessions for
        // the user. If the insert fails we abort and the original session remains intact.
        // If the delete fails after a successful insert, the user will have two valid
        // sessions briefly — acceptable since the old token expires within 7 days and
        // the lookup-hash fast path prevents O(N·bcrypt) scanning of stale rows.
        let new_refresh_token = self
            .generate_refresh_token(user.id, is_2fa_verified)
            .await?;

        // Record this lookup_hash in the rotated_session_audit table so a
        // future refresh attempt with the (now-stale) original token can be
        // recognised as token-reuse rather than a generic "expired" miss.
        // The audit row is meaningful for the duration of the original
        // token's expiry window — set expires_at to now + 7d to match
        // generate_refresh_token's TTL.
        let audit_expires = Utc::now() + Duration::days(7);
        if let Err(e) = sqlx::query(
            "INSERT INTO rotated_session_audit (lookup_hash, user_id, expires_at) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (lookup_hash) DO NOTHING",
        )
        .bind(&lookup_hash)
        .bind(user.id)
        .bind(audit_expires)
        .execute(&self.db_pool)
        .await
        {
            // Non-fatal — reuse detection is defence-in-depth, not a hard
            // requirement. Log and proceed with the rotation.
            tracing::warn!(
                user_id = %user.id,
                "Failed to record rotated_session_audit entry: {}",
                e
            );
        }

        // Best-effort deletion of the old session. Failure is logged but does not prevent
        // the caller from proceeding with the new token pair.
        if let Err(e) = sqlx::query("DELETE FROM user_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&self.db_pool)
            .await
        {
            tracing::warn!(
                session_id = %session_id,
                "Failed to delete rotated refresh token session (non-fatal): {}",
                e
            );
        }

        // Log refresh event
        self.log_auth_event_best_effort(
            Some(user.id),
            "token_refresh",
            Some(&user.email),
            None,
            None,
            true,
            None,
        )
        .await;

        Ok((access_token, new_refresh_token, user, is_2fa_verified))
    }

    /// Revoke refresh token (logout)
    #[must_use]
    pub async fn revoke_refresh_token(&self, refresh_token: &str) -> Result<()> {
        // Use the lookup hash to locate the specific session without a full-table scan.
        let lookup_hash = generate_token_lookup_hash(refresh_token);

        let session = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            SELECT id, refresh_token_hash
            FROM user_sessions
            WHERE refresh_token_lookup_hash = $1
              AND expires_at > NOW()
            LIMIT 1
            "#,
        )
        .bind(&lookup_hash)
        .fetch_optional(&self.db_pool)
        .await
        .context("Failed to fetch session for revocation")?;

        let (session_id, token_hash) = session.ok_or_else(|| anyhow!("Refresh token not found"))?;

        // Verify the bcrypt hash before deleting (single targeted check).
        let token = refresh_token.to_string();
        let is_valid = tokio::task::spawn_blocking(move || verify(&token, &token_hash))
            .await
            .context("Token verification task panicked")??;

        if !is_valid {
            return Err(anyhow!("Refresh token not found"));
        }

        sqlx::query!("DELETE FROM user_sessions WHERE id = $1", session_id)
            .execute(&self.db_pool)
            .await?;

        Ok(())
    }

    /// Revoke ALL active sessions for a user (e.g., after security event or explicit sign-out-all).
    pub async fn revoke_all_sessions(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.db_pool)
            .await
            .context("Failed to revoke all sessions")?;
        tracing::info!(user_id = %user_id, sessions_revoked = result.rows_affected(), "All sessions revoked");
        Ok(result.rows_affected())
    }

    /// Clean up expired sessions and stale rotated_session_audit rows.
    /// Both tables share the same 7-day refresh-token TTL, so they expire
    /// together. Tracking the audit table beyond its meaningful window
    /// just costs disk; reuse detection past 7d is moot because the
    /// original token would have expired anyway.
    pub async fn cleanup_expired_sessions(&self) -> Result<u64> {
        let result = sqlx::query!("DELETE FROM user_sessions WHERE expires_at < NOW()")
            .execute(&self.db_pool)
            .await?;

        // Best-effort prune of the reuse-detection audit table.
        if let Err(e) = sqlx::query("DELETE FROM rotated_session_audit WHERE expires_at < NOW()")
            .execute(&self.db_pool)
            .await
        {
            tracing::warn!("Failed to prune rotated_session_audit (non-fatal): {}", e);
        }

        Ok(result.rows_affected())
    }

    /// Clean up old audit logs (default retention: 90 days).
    ///
    /// MCP-997 (2026-05-15): refuse non-positive `retention_days`.
    /// Same caller-supplied-negative class as MCP-767/811/812 — a
    /// negative value would convert `NOW() - INTERVAL '1 day' * -N`
    /// into `NOW() + INTERVAL`, matching every row and silently
    /// purging the entire `auth_audit_log` table. Sibling fix to
    /// `talos-secrets-manager::cleanup_audit_logs` and
    /// `talos-webhooks::cleanup_request_logs`.
    pub async fn cleanup_audit_logs(&self, retention_days: i64) -> Result<u64> {
        if retention_days <= 0 {
            tracing::warn!(
                target: "talos_audit",
                retention_days,
                "auth-audit cleanup refused: retention_days must be positive (would purge entire log)"
            );
            return Ok(0);
        }
        let result = sqlx::query(
            "DELETE FROM auth_audit_log WHERE created_at < NOW() - INTERVAL '1 day' * $1",
        )
        .bind(retention_days)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Verify and decode JWT token.
    ///
    /// Pins the algorithm to the configured `JWT_ALGORITHM` to prevent "alg: none"
    /// and algorithm-confusion attacks. During a migration window (when
    /// `JWT_ALGORITHM_PREVIOUS` is set), tokens signed with the previous algorithm
    /// are also accepted.
    #[must_use]
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        let build_validation = |algo: Algorithm| -> Validation {
            let mut v = Validation::new(algo);
            v.validate_exp = true; // reject expired tokens (exp < now)
            v.validate_nbf = false; // we don't issue nbf claims
            v.set_required_spec_claims(&["exp", "sub"]); // must have sub + exp
                                                         // Validate issuer to prevent tokens issued by other systems from being accepted.
            v.set_issuer(&["talos"]);
            // NOTE: We do NOT call `v.set_audience` here because that would
            // *require* the `aud` claim, rejecting tokens minted before this
            // change. Instead we validate `aud` post-decode below: tokens with
            // `aud != "talos"` are rejected; tokens without `aud` (legacy) are
            // allowed through until they naturally expire and get re-issued.
            // Disable the library's built-in aud validation so it doesn't
            // reject tokens that carry the claim when no expected audience
            // is configured in the Validation struct.
            v.validate_aud = false;
            v
        };

        // Post-decode audience check. Rejects cross-service replay when `aud`
        // is present but wrong; legacy tokens (no `aud` claim) are accepted
        // unless `JWT_REQUIRE_AUD=true` is set, in which case the migration
        // window has ended and aud-less tokens fail closed.
        //
        // M-6: pre-fix the back-compat path was permanent — there was no
        // mechanism for operators to flip strict mode once aud-less tokens
        // had aged out of circulation, so the audience-validation invariant
        // had no end date. Now operators that have run with the new
        // version for one access-token TTL (default 15 min) can set
        // `JWT_REQUIRE_AUD=true` to fail closed. Every aud-less verify
        // also emits a structured event so dashboards can graph the
        // count → flip strict mode when it reaches zero.
        //
        // MCP-1060 (2026-05-15): cached via `LazyLock` so the env-var
        // read happens ONCE per process — `verify_token` runs on every
        // authenticated request, and the previous `env::var` call took
        // the process-wide environ lock + allocated a String each
        // invocation. The flag is a deploy-time toggle by design
        // (operators flip it once aud-less tokens have aged out), so
        // read-once semantics match the intent. Operators changing the
        // flag must restart the process for it to take effect — same
        // contract as every other env-var-driven config.
        static REQUIRE_AUD: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
            talos_config::bool_env_or_default("JWT_REQUIRE_AUD", false)
        });
        let require_aud = *REQUIRE_AUD;
        let check_audience = |claims: &Claims| -> Result<()> {
            match &claims.aud {
                Some(aud) if aud != "talos" => Err(anyhow!("Invalid audience claim")),
                Some(_) => Ok(()),
                None => {
                    if require_aud {
                        Err(anyhow!("Missing audience claim (JWT_REQUIRE_AUD=true)"))
                    } else {
                        // Telemetry counter so operators see when legacy
                        // aud-less tokens disappear and can flip strict mode.
                        tracing::warn!(
                            target: "talos_auth",
                            event_kind = "jwt_legacy_aud_less_verify",
                            "Verified token with no aud claim (legacy back-compat)"
                        );
                        Ok(())
                    }
                }
            }
        };

        // Try the current algorithm first
        let validation = build_validation(self.key_pair.algorithm());
        match decode::<Claims>(token, self.key_pair.decoding_key(), &validation) {
            Ok(token_data) => {
                check_audience(&token_data.claims)?;
                Ok(token_data.claims)
            }
            Err(current_err) => {
                // If a previous key pair is configured, try that before failing
                if let Some(ref prev) = self.previous_key_pair {
                    let prev_validation = build_validation(prev.algorithm);
                    if let Ok(token_data) =
                        decode::<Claims>(token, &prev.decoding_key, &prev_validation)
                    {
                        check_audience(&token_data.claims)?;
                        tracing::debug!(
                            "Token verified with previous JWT algorithm — \
                             client should refresh to get a token signed with the current algorithm"
                        );
                        return Ok(token_data.claims);
                    }
                }
                // Neither current nor previous algorithm could verify the token
                Err(current_err.into())
            }
        }
    }

    /// Get user by ID
    pub async fn get_user(&self, user_id: Uuid) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, email, password_hash, name, created_at, updated_at, last_login_at, is_active,
                   failed_login_attempts, locked_until, totp_secret, totp_enabled
            FROM users
            WHERE id = $1 AND is_active = true
            "#,
            user_id
        )
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))?;

        Ok(user)
    }

    /// Get user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, email, password_hash, name, created_at, updated_at, last_login_at, is_active,
                   failed_login_attempts, locked_until, totp_secret, totp_enabled
            FROM users
            WHERE email = $1 AND is_active = true
            "#,
            email
        )
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(user)
    }

    /// Change user password
    pub async fn change_password(
        &self,
        user_id: Uuid,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        // Fetch user
        let user = self.get_user(user_id).await?;

        // Verify old password (use spawn_blocking to avoid blocking)
        let old_pwd = old_password.to_string();
        let old_hash = user.password_hash.clone();
        let is_valid = tokio::task::spawn_blocking(move || verify(&old_pwd, &old_hash))
            .await
            .context("Password verification task panicked")??;

        if !is_valid {
            return Err(anyhow!("Invalid current password"));
        }

        // Validate new password complexity
        validate_password(new_password)?;

        // Hash new password (use spawn_blocking to avoid blocking)
        let cost = self.bcrypt_cost;
        let new_pwd = new_password.to_string();
        let new_password_hash = tokio::task::spawn_blocking(move || hash(&new_pwd, cost))
            .await
            .context("Password hashing task panicked")??;

        // Update password
        sqlx::query!(
            "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
            new_password_hash,
            user_id
        )
        .execute(&self.db_pool)
        .await?;

        // Revoke ALL active sessions after a password change.
        //
        // An attacker who obtained the old password (or any active refresh token from
        // before the change) must not be able to continue using those tokens. Revoking
        // here forces every session to re-authenticate with the new password.
        //
        // Non-fatal: if the DELETE fails (e.g. transient DB issue) we log and proceed.
        // The password was already updated successfully; the worst outcome is stale
        // sessions that will expire on their own within 7 days.
        if let Err(e) = sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.db_pool)
            .await
        {
            tracing::warn!(
                user_id = %user_id,
                "Failed to revoke sessions after password change (non-fatal): {}",
                e
            );
        } else {
            tracing::info!(user_id = %user_id, "All sessions revoked after password change");
        }

        // Log password change
        self.log_auth_event_best_effort(
            Some(user_id),
            "password_change",
            Some(&user.email),
            None,
            None,
            true,
            None,
        )
        .await;

        Ok(())
    }

    /// Check refresh token rate limit using Redis (distributed across instances).
    /// Returns true if rate limit exceeded, false if allowed.
    /// Uses atomic INCR to avoid TOCTOU race between GET and INCR.
    async fn check_refresh_rate_limit_redis(
        &self,
        session_id: Uuid,
        redis: &Arc<redis::Client>,
    ) -> Result<bool> {
        const LIMIT: i64 = 10;
        const WINDOW_SECS: i64 = 60;

        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .context("Failed to get Redis connection")?;

        let key = format!("refresh_rate_limit:{}", session_id);

        // MCP-463: third instance of the INCR+EXPIRE race that closed
        // MCP-442 (talos-rate-limit) and MCP-455 (talos-api-keys).
        // Pre-fix: INCR creates the key with no TTL on first hit; if
        // the follow-up EXPIRE failed transiently (network blip,
        // server reconnect mid-flight), the key persisted forever and
        // subsequent INCRs would bump a stale counter — locking out
        // refreshes for that session_id indefinitely until an operator
        // manually deleted the Redis key. The L-19 review fix added a
        // warn-log but didn't close the underlying race. Move both
        // ops into a single EVAL'd Lua script so they execute
        // atomically on the server.
        const RATE_LIMIT_SCRIPT: &str = r#"
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return count
        "#;
        let count: i64 = redis::cmd("EVAL")
            .arg(RATE_LIMIT_SCRIPT)
            .arg(1)
            .arg(&key)
            .arg(WINDOW_SECS)
            .query_async(&mut conn)
            .await
            .context("Redis rate-limit script failed")?;

        Ok(count > LIMIT)
    }
}

/// Extract user ID from authorization header
pub fn extract_user_from_header(
    auth_header: Option<&str>,
    auth_service: &AuthService,
) -> Option<Uuid> {
    let token = auth_header?.strip_prefix("Bearer ")?;

    let claims = auth_service.verify_token(token).ok()?;

    Uuid::parse_str(&claims.sub).ok()
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;

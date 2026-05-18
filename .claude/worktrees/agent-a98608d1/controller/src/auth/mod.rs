// AuthService contains many methods not exercised by the current test suite.
#![allow(dead_code, unused_imports, unused_mut, unused_variables)]
use anyhow::{anyhow, Context, Result};
use bcrypt::{hash, verify};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use uuid::Uuid;

static REFRESH_RATE_LIMITER: OnceLock<Mutex<HashMap<Uuid, (usize, Instant)>>> = OnceLock::new();

/// User model
#[derive(Clone)]
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

/// JWT Claims
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub email: String,
    pub exp: usize, // expiration timestamp
    pub iat: usize, // issued at timestamp
}

/// Validate email format
fn validate_email(email: &str) -> Result<()> {
    // Basic email validation regex
    let email_regex_result = regex::Regex::new(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$",
    );

    if let Ok(email_regex) = email_regex_result {
        if !email_regex.is_match(email) {
            return Err(anyhow!("Invalid email format"));
        }
    }

    if email.len() > 254 {
        return Err(anyhow!("Email address is too long"));
    }

    Ok(())
}

/// Generate SHA256 hash for fast token lookups
/// This is NOT for security (bcrypt is still used for that), but for efficient database queries
fn generate_token_lookup_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
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

    Ok(())
}

/// Authentication service
pub struct AuthService {
    pub db_pool: Pool<Postgres>,
    jwt_secret: String,
    bcrypt_cost: u32,
}

impl AuthService {
    pub fn new(
        db_pool: Pool<Postgres>,
        jwt_secret: String,
        bcrypt_cost: u32,
    ) -> anyhow::Result<Self> {
        // Validate bcrypt cost (4-31 per bcrypt spec, but 10-14 recommended for production)
        // Validate bcrypt cost using a range check that Clippy can understand.
        if !(10..=14).contains(&bcrypt_cost) {
            anyhow::bail!("BCRYPT_COST must be between 10 and 14 (recommended: 12)");
        }

        Ok(Self {
            db_pool,
            jwt_secret,
            bcrypt_cost,
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

    /// Create a new user (signup)
    pub async fn create_user(
        &self,
        email: &str,
        password: &str,
        name: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Uuid> {
        // Validate email format
        validate_email(email)?;

        // Validate password complexity
        validate_password(password)?;

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
                anyhow!("Failed to create user: {}", e)
            }
        })?;

        // Log successful signup
        self.log_auth_event(
            Some(user_id),
            "signup",
            Some(email),
            ip_address,
            user_agent,
            true,
            None,
        )
        .await
        .ok(); // Don't fail signup if logging fails

        Ok(user_id)
    }

    /// Authenticate user and return access token, refresh token, and user (login)
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<(String, String, User)> {
        // Fetch user by email
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

        let mut user = match user {
            Some(u) => u,
            None => {
                // Log failed login attempt (user not found)
                self.log_auth_event(
                    None,
                    "login_failed",
                    Some(email),
                    ip_address,
                    user_agent,
                    false,
                    Some("User not found or inactive"),
                )
                .await
                .ok();
                return Err(anyhow!("Invalid email or password"));
            }
        };

        // Check if account is locked
        if let Some(locked_until) = user.locked_until {
            if locked_until > Utc::now() {
                let remaining = (locked_until - Utc::now()).num_seconds();
                self.log_auth_event(
                    Some(user.id),
                    "login_failed",
                    Some(email),
                    ip_address,
                    user_agent,
                    false,
                    Some(&format!("Account locked for {} more seconds", remaining)),
                )
                .await
                .ok();
                return Err(anyhow!(
                    "Account is locked due to too many failed login attempts. Try again in {} seconds.",
                    remaining
                ));
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
            // Increment failed login attempts
            let new_attempts = user.failed_login_attempts + 1;
            const MAX_ATTEMPTS: i32 = 5; // Production security: lock after 5 failed attempts
            const LOCKOUT_DURATION_MINUTES: i64 = 15;

            if new_attempts >= MAX_ATTEMPTS {
                // Lock the account for 15 minutes
                let locked_until = Utc::now() + Duration::minutes(LOCKOUT_DURATION_MINUTES);
                sqlx::query!(
                    "UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3",
                    new_attempts,
                    locked_until,
                    user.id
                )
                .execute(&self.db_pool)
                .await?;

                // Log account lockout
                self.log_auth_event(
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
                .await
                .ok();

                return Err(anyhow!(
                    "Account locked due to too many failed login attempts. Try again in {} minutes.",
                    LOCKOUT_DURATION_MINUTES
                ));
            } else {
                // Just increment the counter
                sqlx::query!(
                    "UPDATE users SET failed_login_attempts = $1 WHERE id = $2",
                    new_attempts,
                    user.id
                )
                .execute(&self.db_pool)
                .await?;

                // Log failed login attempt (wrong password)
                self.log_auth_event(
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
                .await
                .ok();

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

        // Generate access token (short-lived: 15 minutes)
        let access_token = self.generate_access_token(&user)?;

        // Generate refresh token (long-lived: 7 days)
        let refresh_token = self.generate_refresh_token(user.id).await?;

        // Log successful login
        self.log_auth_event(
            Some(user.id),
            "login_success",
            Some(email),
            ip_address,
            user_agent,
            true,
            None,
        )
        .await
        .ok();

        Ok((access_token, refresh_token, user))
    }

    /// Generate access token for a user (short-lived: 15 minutes)
    pub fn generate_access_token(&self, user: &User) -> Result<String> {
        let now = Utc::now();
        let expiration = now + Duration::minutes(15); // Short-lived access token

        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            exp: expiration.timestamp() as usize,
            iat: now.timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    /// Generate JWT token for a user (kept for backward compatibility)
    pub fn generate_token(&self, user: &User) -> Result<String> {
        self.generate_access_token(user)
    }

    /// Generate refresh token and store in database (long-lived: 7 days)
    pub async fn generate_refresh_token(&self, user_id: Uuid) -> Result<String> {
        use rand::Rng;

        // Generate token and lookup hash before any async operations
        let (refresh_token, lookup_hash, expires_at) = {
            // Generate cryptographically secure random token (32 bytes = 256 bits)
            let mut rng = rand::thread_rng();
            let token_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            let refresh_token = hex::encode(&token_bytes);

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
            "INSERT INTO user_sessions (user_id, refresh_token_hash, refresh_token_lookup_hash, expires_at)
             VALUES ($1, $2, $3, $4)"
        )
        .bind(user_id)
        .bind(&token_hash)
        .bind(&lookup_hash)
        .bind(expires_at)
        .execute(&self.db_pool)
        .await
        .context("Failed to store refresh token")?;

        Ok(refresh_token)
    }

    /// Validate refresh token and generate new access token
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<(String, User)> {
        // Generate lookup hash for efficient query
        let lookup_hash = generate_token_lookup_hash(refresh_token);

        // Find session by lookup hash (much faster than fetching all sessions)
        // Note: lookup_hash column may be NULL for old sessions created before this optimization
        let session = sqlx::query_as::<_, (Uuid, Uuid, String, DateTime<Utc>)>(
            r#"
            SELECT id, user_id, refresh_token_hash, expires_at
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
        let session = session.ok_or_else(|| anyhow!("Invalid or expired refresh token"))?;

        // Rate limiting by session ID to prevent spam and CPU exhaustion from bcrypt
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

            let (count, last_time) = limiter.entry(session.0).or_insert((0, now));
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
        let (session_id, user_id, _token_hash, _expires_at) = session;

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
        let access_token = self.generate_access_token(&user)?;

        // Log refresh event
        self.log_auth_event(
            Some(user.id),
            "token_refresh",
            Some(&user.email),
            None,
            None,
            true,
            None,
        )
        .await
        .ok();

        Ok((access_token, user))
    }

    /// Revoke refresh token (logout)
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

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<u64> {
        let result = sqlx::query!("DELETE FROM user_sessions WHERE expires_at < NOW()")
            .execute(&self.db_pool)
            .await?;

        Ok(result.rows_affected())
    }

    /// Clean up old audit logs (default retention: 90 days)
    pub async fn cleanup_audit_logs(&self, retention_days: i64) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM auth_audit_log WHERE created_at < NOW() - INTERVAL '1 day' * $1",
        )
        .bind(retention_days)
        .execute(&self.db_pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Verify and decode JWT token
    pub fn verify_token(&self, token: &str) -> Result<Claims> {
        // Pin algorithm to HS256 to prevent "alg: none" and algorithm-confusion attacks.
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )?;

        Ok(token_data.claims)
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

        // Log password change
        self.log_auth_event(
            Some(user_id),
            "password_change",
            Some(&user.email),
            None,
            None,
            true,
            None,
        )
        .await
        .ok();

        Ok(())
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

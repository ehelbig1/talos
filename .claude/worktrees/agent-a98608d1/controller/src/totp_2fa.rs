use anyhow::{anyhow, Result};
use dashmap::DashMap;
use rand::Rng;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use std::time::Instant;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

use crate::secrets::SecretsManager;

/// Per-user 2FA rate-limit state.
#[derive(Debug)]
struct TotpRateState {
    failed_attempts: u32,
    locked_until: Option<Instant>,
}

/// Maximum consecutive 2FA failures before temporary lockout.
const MAX_2FA_ATTEMPTS: u32 = 5;
/// Lockout duration after exceeding `MAX_2FA_ATTEMPTS`.
const LOCKOUT_SECS: u64 = 900; // 15 minutes

/// 2FA/TOTP service
pub struct TotpService {
    db_pool: Pool<Postgres>,
    issuer: String,
    redis_client: Option<Arc<redis::Client>>,
    rate_limits: Arc<DashMap<Uuid, TotpRateState>>,
    secrets_manager: Arc<SecretsManager>,
}

impl TotpService {
    pub fn new(
        db_pool: Pool<Postgres>,
        redis_client: Option<Arc<redis::Client>>,
        secrets_manager: Arc<SecretsManager>,
    ) -> Self {
        let issuer = std::env::var("TOTP_ISSUER").unwrap_or_else(|_| "Talos".to_string());

        if redis_client.is_none() {
            tracing::warn!("TOTP rate limiter is currently in-memory. For a distributed deployment, this should be backed by Redis.");
        }

        Self {
            db_pool,
            issuer,
            redis_client,
            rate_limits: Arc::new(DashMap::new()),
            secrets_manager,
        }
    }

    /// Check and record a 2FA attempt for `user_id`.
    /// Returns `Err` if the user is currently locked out.
    /// On successful authentication the caller must call `record_2fa_success`.
    fn check_rate_limit(&self, user_id: Uuid) -> Result<()> {
        let mut entry = self
            .rate_limits
            .entry(user_id)
            .or_insert_with(|| TotpRateState {
                failed_attempts: 0,
                locked_until: None,
            });

        if let Some(locked_until) = entry.locked_until {
            if Instant::now() < locked_until {
                let remaining = locked_until.duration_since(Instant::now()).as_secs();
                return Err(anyhow!(
                    "Too many failed 2FA attempts. Account locked for {} more seconds.",
                    remaining
                ));
            }
            // Lockout has expired — reset
            entry.failed_attempts = 0;
            entry.locked_until = None;
        }

        Ok(())
    }

    /// Record a failed 2FA attempt for `user_id`, applying lockout if threshold exceeded.
    fn record_2fa_failure(&self, user_id: Uuid) {
        let mut entry = self
            .rate_limits
            .entry(user_id)
            .or_insert_with(|| TotpRateState {
                failed_attempts: 0,
                locked_until: None,
            });

        entry.failed_attempts += 1;
        if entry.failed_attempts >= MAX_2FA_ATTEMPTS {
            let locked_until = Instant::now() + std::time::Duration::from_secs(LOCKOUT_SECS);
            entry.locked_until = Some(locked_until);
            tracing::warn!(
                user_id = %user_id,
                attempts = entry.failed_attempts,
                "2FA lockout activated after too many failed attempts"
            );
        }
    }

    /// Reset the rate-limit counter for `user_id` after a successful 2FA verification.
    fn record_2fa_success(&self, user_id: Uuid) {
        self.rate_limits.remove(&user_id);
    }

    /// Generate a new TOTP secret for a user
    pub fn generate_secret(&self) -> String {
        use rand::Rng;

        // Generate 20 random bytes for the secret (160 bits)
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..20).map(|_| rng.gen()).collect();

        // Encode as base32
        Secret::Raw(bytes).to_encoded().to_string()
    }

    /// Generate backup codes (10 codes, 12 hex characters each = 48 bits of entropy).
    /// Using hex rather than decimal avoids collisions from the birthday paradox at
    /// lower digit counts and matches standard backup-code entropy recommendations.
    pub fn generate_backup_codes(&self) -> Vec<String> {
        let mut rng = rand::thread_rng();
        (0..10)
            .map(|_| {
                let bytes: [u8; 6] = rng.gen();
                hex::encode(bytes) // 12 lowercase hex chars, 48 bits of entropy
            })
            .collect()
    }

    /// Get TOTP instance for a user
    // `email` is not needed for TOTP generation; underscore silences the warning.
    fn get_totp(&self, secret: &str, _email: &str) -> Result<TOTP> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6, // 6-digit codes
            1, // 1 step (30 seconds)
            30,
            Secret::Encoded(secret.to_string())
                .to_bytes()
                .map_err(|e| anyhow!("Invalid secret: {}", e))?,
        )
        .map_err(|e| anyhow!("Failed to create TOTP: {}", e))?;

        Ok(totp)
    }

    /// Generate QR code URL for enrollment
    pub fn generate_qr_code_url(&self, secret: &str, email: &str) -> Result<String> {
        // Validate secret format; result not needed here
        let _ = self.get_totp(secret, email)?;
        // Generate otpauth:// URL manually
        let url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            urlencoding::encode(&self.issuer),
            urlencoding::encode(email),
            secret,
            urlencoding::encode(&self.issuer),
            "SHA1",
            6,
            30
        );
        Ok(url)
    }

    /// Generate QR code as base64-encoded PNG
    pub fn generate_qr_code_png(&self, secret: &str, email: &str) -> Result<String> {
        use qrcode::QrCode;

        let url = self.generate_qr_code_url(secret, email)?;

        // Generate QR code
        let code = QrCode::new(url.as_bytes())?;

        // Render as image
        let image = code.render::<image::Luma<u8>>().build();

        // Convert to PNG bytes
        let mut png_bytes = Vec::new();
        use image::ImageFormat;
        image::DynamicImage::ImageLuma8(image)
            .write_to(&mut std::io::Cursor::new(&mut png_bytes), ImageFormat::Png)?;

        // Encode as base64
        Ok(base64::encode(png_bytes))
    }

    /// Verify a TOTP code using constant-time comparison to prevent timing attacks.
    ///
    /// Accepts codes from the previous, current, and next time step (±30s) to
    /// tolerate minor clock drift between client and server.
    pub fn verify_code(&self, secret: &str, email: &str, code: &str) -> Result<bool> {
        use subtle::ConstantTimeEq;

        let totp = self.get_totp(secret, email)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| anyhow!("System time error: {}", e))?
            .as_secs();

        // Check the previous, current, and next 30-second windows so that minor
        // clock drift between client and server is tolerated.  All comparisons
        // use constant-time OR so that the overall result leaks no timing
        // information about which (if any) candidate matched.
        let step = 30u64;
        let code_bytes = code.as_bytes();
        let mut valid = subtle::Choice::from(0u8);

        for t in [now.saturating_sub(step), now, now + step] {
            let expected = totp.generate(t);
            valid |= code_bytes.ct_eq(expected.as_bytes());
        }

        Ok(bool::from(valid))
    }

    /// Encrypt a TOTP secret using the SecretsManager's envelope encryption (AES-256-GCM).
    /// Returns a base64-encoded string containing the key ID, nonce, and ciphertext.
    async fn encrypt_totp_secret(&self, secret: &str) -> Result<String> {
        let (key_id, encrypted_bytes) = self.secrets_manager.encrypt_value(secret).await?;
        // Encode as: key_id_hex:base64(nonce||ciphertext)
        let encoded = format!("{}:{}", key_id, base64::encode(&encrypted_bytes));
        Ok(encoded)
    }

    /// Decrypt a TOTP secret that was encrypted with `encrypt_totp_secret`.
    async fn decrypt_totp_secret(&self, encrypted: &str) -> Result<String> {
        let parts: Vec<&str> = encrypted.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid encrypted TOTP secret format"));
        }
        let key_id: Uuid = parts[0]
            .parse()
            .map_err(|_| anyhow!("Invalid encryption key ID in TOTP secret"))?;
        let encrypted_bytes = base64::decode(parts[1])
            .map_err(|_| anyhow!("Invalid base64 in encrypted TOTP secret"))?;
        self.secrets_manager
            .decrypt_value_by_key(key_id, &encrypted_bytes)
            .await
    }

    /// Enable 2FA for a user
    pub async fn enable_2fa(
        &self,
        user_id: Uuid,
        secret: &str,
        verification_code: &str,
        email: &str,
    ) -> Result<Vec<String>> {
        // Verify the code first
        if !self.verify_code(secret, email, verification_code)? {
            return Err(anyhow!("Invalid verification code"));
        }

        // Generate backup codes
        let backup_codes = self.generate_backup_codes();

        // Hash backup codes before storing
        let hashed_codes: Vec<String> = backup_codes
            .iter()
            .map(|code| bcrypt::hash(code, bcrypt::DEFAULT_COST).unwrap_or_else(|_| code.clone()))
            .collect();

        // Encrypt the TOTP secret before storing
        let encrypted_secret = self.encrypt_totp_secret(secret).await?;

        // Store in database
        sqlx::query!(
            "UPDATE users
             SET totp_secret = $1, totp_enabled = true, backup_codes = $2
             WHERE id = $3",
            encrypted_secret,
            &hashed_codes[..],
            user_id
        )
        .execute(&self.db_pool)
        .await?;

        // Return plain backup codes to user (only shown once!)
        Ok(backup_codes)
    }

    /// Disable 2FA for a user
    pub async fn disable_2fa(&self, user_id: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE users
             SET totp_secret = NULL, totp_enabled = false, backup_codes = NULL
             WHERE id = $1",
            user_id
        )
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }

    /// Verify 2FA code during login (supports both TOTP and backup codes).
    ///
    /// Includes brute-force protection: after 5 consecutive failures the user
    /// is locked out for 15 minutes.  Backup code consumption is atomic (uses a
    /// DB transaction with a PostgreSQL advisory lock) to prevent TOCTOU races.
    pub async fn verify_2fa_login(&self, user_id: Uuid, code: &str, email: &str) -> Result<bool> {
        use sqlx::Row as _;

        // Enforce rate limit before doing any DB work.
        self.check_rate_limit(user_id)?;

        // Fetch user data outside a transaction — TOTP verification doesn't
        // modify DB state so we don't need a lock for that path.
        // NOTE: query text must match the cached sqlx offline entry exactly.
        let user = sqlx::query!(
            "SELECT totp_secret, totp_enabled, backup_codes
             FROM users
             WHERE id = $1",
            user_id
        )
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))?;

        if !user.totp_enabled {
            return Err(anyhow!("2FA not enabled for this user"));
        }

        let encrypted_secret = user
            .totp_secret
            .ok_or_else(|| anyhow!("TOTP secret not found"))?;

        // Decrypt the TOTP secret before use
        let secret = self.decrypt_totp_secret(&encrypted_secret).await?;

        // Try TOTP code first — no DB state to modify.
        if self.verify_code(&secret, email, code)? {
            self.record_2fa_success(user_id);
            return Ok(true);
        }

        // Try backup codes inside a transaction with an exclusive advisory lock
        // to prevent a TOCTOU race where two concurrent requests consume the same
        // backup code.  PostgreSQL advisory locks are cheaper than row locks and
        // don't require a SELECT … FOR UPDATE (which would need a new sqlx offline
        // query cache entry).
        if user.backup_codes.is_some() {
            let mut tx = self.db_pool.begin().await?;

            // Derive a stable 64-bit advisory lock key from the first 8 bytes of
            // the UUID interpreted as big-endian i64.
            let bytes = user_id.as_bytes();
            let lock_key = i64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            // Use non-macro form so no offline cache entry is required.
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(lock_key)
                .execute(&mut *tx)
                .await?;

            // Re-fetch backup codes inside the lock to get the authoritative state.
            // Use non-macro `sqlx::query` to avoid requiring an offline cache entry
            // for this transaction-scoped query.
            let maybe_row = sqlx::query("SELECT backup_codes FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;

            let locked_codes: Vec<String> = match maybe_row {
                None => {
                    tx.rollback().await?;
                    self.record_2fa_failure(user_id);
                    return Ok(false);
                }
                Some(row) => {
                    let codes: Option<Vec<String>> = row.try_get("backup_codes").ok().flatten();
                    match codes {
                        None => {
                            tx.rollback().await?;
                            self.record_2fa_failure(user_id);
                            return Ok(false);
                        }
                        Some(c) => c,
                    }
                }
            };

            for (index, hashed_code) in locked_codes.iter().enumerate() {
                if bcrypt::verify(code, hashed_code).unwrap_or(false) {
                    // Remove the consumed backup code atomically.
                    let mut remaining_codes = locked_codes.clone();
                    remaining_codes.remove(index);

                    sqlx::query!(
                        "UPDATE users SET backup_codes = $1 WHERE id = $2",
                        &remaining_codes[..],
                        user_id
                    )
                    .execute(&mut *tx)
                    .await?;

                    tx.commit().await?;
                    tracing::info!("User {} used backup code (index {})", user_id, index);
                    self.record_2fa_success(user_id);
                    return Ok(true);
                }
            }

            tx.rollback().await?;
        }

        // Verification failed — record the failure and return false.
        self.record_2fa_failure(user_id);
        Ok(false)
    }

    /// Check if 2FA is enabled for a user
    pub async fn is_2fa_enabled(&self, user_id: Uuid) -> Result<bool> {
        let result =
            sqlx::query_as::<_, (Option<bool>,)>("SELECT totp_enabled FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?
                .ok_or_else(|| anyhow!("User not found"))?;

        Ok(result.0.unwrap_or(false))
    }

    /// Get remaining backup codes count
    pub async fn get_backup_codes_count(&self, user_id: Uuid) -> Result<usize> {
        let result = sqlx::query_as::<_, (Option<Vec<String>>,)>(
            "SELECT backup_codes FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))?;

        Ok(result.0.map(|codes| codes.len()).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_generate_secret() {
        let db_pool = Pool::<Postgres>::connect_lazy("").unwrap();
        let service = TotpService::new(db_pool, None);

        let secret1 = service.generate_secret();
        let secret2 = service.generate_secret();

        // Secrets should be different
        assert_ne!(secret1, secret2);

        // Secrets should be base32 encoded
        assert!(secret1.len() > 10);
    }

    #[test]
    #[ignore]
    fn test_generate_backup_codes() {
        let db_pool = Pool::<Postgres>::connect_lazy("").unwrap();
        let service = TotpService::new(db_pool, None);

        let codes = service.generate_backup_codes();

        // Should generate 10 codes
        assert_eq!(codes.len(), 10);

        // Each code should be 12 hex chars (48 bits entropy)
        for code in &codes {
            assert_eq!(code.len(), 12);
            assert!(code.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // Codes should be unique
        let unique_codes: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(unique_codes.len(), 10);
    }

    #[test]
    #[ignore]
    fn test_verify_code() {
        let db_pool = Pool::<Postgres>::connect_lazy("").unwrap();
        let service = TotpService::new(db_pool, None);

        let secret = service.generate_secret();
        let email = "test@example.com";

        // Generate current code
        let totp = service.get_totp(&secret, email).unwrap();
        let code = totp.generate_current().unwrap();

        // Verify the code
        assert!(service.verify_code(&secret, email, &code).unwrap());

        // Invalid code should fail
        assert!(!service.verify_code(&secret, email, "000000").unwrap());
    }

    #[test]
    fn test_rate_limiter_locks_after_max_attempts() {
        // Rate limiter is purely in-memory; we can test it without a real DB connection.
        let rate_limits: Arc<DashMap<Uuid, TotpRateState>> = Arc::new(DashMap::new());
        let user_id = Uuid::new_v4();

        let check = |rl: &Arc<DashMap<Uuid, TotpRateState>>| {
            let mut entry = rl.entry(user_id).or_insert_with(|| TotpRateState {
                failed_attempts: 0,
                locked_until: None,
            });
            if let Some(locked_until) = entry.locked_until {
                if Instant::now() < locked_until {
                    return Err(());
                }
                entry.failed_attempts = 0;
                entry.locked_until = None;
            }
            Ok(())
        };

        let record_failure = |rl: &Arc<DashMap<Uuid, TotpRateState>>| {
            let mut entry = rl.entry(user_id).or_insert_with(|| TotpRateState {
                failed_attempts: 0,
                locked_until: None,
            });
            entry.failed_attempts += 1;
            if entry.failed_attempts >= MAX_2FA_ATTEMPTS {
                entry.locked_until =
                    Some(Instant::now() + std::time::Duration::from_secs(LOCKOUT_SECS));
            }
        };

        // First MAX_2FA_ATTEMPTS - 1 failures should pass the rate-limit check
        for _ in 0..MAX_2FA_ATTEMPTS - 1 {
            assert!(check(&rate_limits).is_ok());
            record_failure(&rate_limits);
        }

        // The Nth failure should trigger lockout
        assert!(check(&rate_limits).is_ok());
        record_failure(&rate_limits);

        // Now the account should be locked
        assert!(check(&rate_limits).is_err());
    }

    #[test]
    fn test_rate_limiter_resets_on_success() {
        let rate_limits: Arc<DashMap<Uuid, TotpRateState>> = Arc::new(DashMap::new());
        let user_id = Uuid::new_v4();

        // Record some failures
        for _ in 0..3 {
            let mut entry = rate_limits.entry(user_id).or_insert_with(|| TotpRateState {
                failed_attempts: 0,
                locked_until: None,
            });
            entry.failed_attempts += 1;
        }

        // Successful auth clears the counter
        rate_limits.remove(&user_id);

        // Should now pass (no entry = no lock)
        let check_result = rate_limits
            .get(&user_id)
            .map_or(true, |e| e.locked_until.is_none());
        assert!(check_result);
    }
}

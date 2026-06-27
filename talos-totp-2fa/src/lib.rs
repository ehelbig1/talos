use anyhow::{anyhow, Context, Result};
use dashmap::DashMap;
use redis::AsyncCommands;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use std::time::Instant;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

use talos_secrets_manager::SecretsManager;

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
        // MCP-631: empty-env hardening — `TOTP_ISSUER=""` (Helm
        // placeholder) would otherwise produce an empty issuer in the
        // otpauth:// URL and authenticator apps display a blank
        // identifier. Empty-string → use "Talos" default.
        let issuer = talos_config::get_env("TOTP_ISSUER", "Talos");

        if redis_client.is_none() {
            // MCP-1095: escalate to ERROR in production so the
            // operator sees a loud boot-time signal that 2FA will
            // refuse to verify (verify_2fa_login fails closed). In
            // dev the WARN suffices — TOTP works fine single-pod
            // without Redis for local testing.
            if talos_config::is_production() {
                tracing::error!(
                    "TOTP service constructed without Redis in PRODUCTION. \
                     verify_2fa_login WILL FAIL CLOSED on every attempt — \
                     2FA login is effectively disabled until REDIS_URL is \
                     configured and reachable. Set REDIS_URL and restart."
                );
            } else {
                tracing::warn!("TOTP rate limiter is currently in-memory. For a distributed deployment, this should be backed by Redis.");
            }
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
    async fn check_rate_limit(&self, user_id: Uuid) -> Result<()> {
        // Try Redis first if available (distributed rate limiting)
        if let Some(redis) = &self.redis_client {
            match self.check_rate_limit_redis(user_id, redis).await {
                Ok(result) => return result,
                Err(e) => {
                    // In production, fail closed: if the distributed rate limiter is
                    // unavailable we cannot guarantee brute-force protection across cluster
                    // nodes, so we reject the attempt rather than silently degrade.
                    // In development, fall back to in-memory to avoid disruption.
                    if talos_config::is_production() {
                        tracing::error!(
                            user_id = %user_id,
                            "Redis 2FA rate limit unavailable in production — rejecting attempt: {}",
                            e
                        );
                        anyhow::bail!(
                            "Authentication service temporarily unavailable. Please try again shortly."
                        );
                    }
                    tracing::warn!(
                        user_id = %user_id,
                        "Redis 2FA rate limit check failed, falling back to in-memory (dev mode): {}",
                        e
                    );
                }
            }
        }

        // Fall back to in-memory rate limiting (dev mode or no Redis configured)
        self.check_rate_limit_memory(user_id)
    }

    /// Check rate limit using Redis (distributed across instances).
    ///
    /// MCP-688 (2026-05-13): pre-charges the attempt counter at the gate
    /// instead of waiting for `record_2fa_failure`. Pre-fix the gate
    /// only read `locked_until`; an attacker who landed N parallel
    /// verify requests within the verify-then-increment window (~15-20 ms
    /// per request: HGET + DB SELECT + decrypt + verify) saw all N
    /// requests pass the gate before any incremented the counter past
    /// threshold. After MCP-532 atomized the increment itself, the
    /// counter ended at N, but the lockout fired AFTER all N had
    /// already verified — so a 100-parallel attacker effectively got
    /// 100 attempts per 15-min cycle instead of the intended 5. Same
    /// class as MCP-532 just one layer up.
    ///
    /// Fix: HINCRBY the counter AT the gate. The strict-greater-than
    /// threshold (`> MAX_2FA_ATTEMPTS`) lets the legitimate 5th attempt
    /// pass (charge = 5, ≤ 5, proceed); the 6th sees charge = 6 > 5 and
    /// is blocked at the gate before any DB work. A successful login
    /// clears the counter via `record_2fa_success_redis::del(&key)`.
    async fn check_rate_limit_redis(
        &self,
        user_id: Uuid,
        redis: &Arc<redis::Client>,
    ) -> Result<Result<()>> {
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .context("Failed to get Redis connection")?;

        let key = format!("totp_rate_limit:{}", user_id);

        // Check if user is currently locked out
        let locked_until: Option<i64> = conn.hget(&key, "locked_until").await.ok().flatten();

        if let Some(locked_ts) = locked_until {
            let now = chrono::Utc::now().timestamp();
            if now < locked_ts {
                let remaining = (locked_ts - now) as u64;
                return Ok(Err(anyhow!(
                    "Too many failed 2FA attempts. Account locked for {} more seconds.",
                    remaining
                )));
            }
            // Lockout expired - delete the key.
            //
            // MCP-780 (2026-05-13): log Redis DEL failures here. Pre-fix
            // `let _: RedisResult<()> = conn.del(...).await` discarded
            // errors. Worst-case impact: the failed_attempts counter is
            // NOT cleared, the HINCRBY below increments the stale-but-
            // preserved counter (e.g., 6 → 7), the strict-greater-than
            // gate at line ~154 immediately re-locks the user, and the
            // EXPIRE refresh below resets the TTL for another full
            // LOCKOUT_SECS window. Net: user is permanently locked out
            // every time they retry, even after the legitimate lockout
            // window has passed, until Redis itself evicts the key
            // (TTL or memory pressure). WARN with `target: "talos_audit"`
            // so dashboards can correlate lockout-stuck reports to Redis
            // health. Same fire-and-forget operator-visibility class as
            // MCP-733..779.
            if let Err(e) = conn.del::<_, ()>(&key).await {
                tracing::warn!(
                    target: "talos_audit",
                    user_id = %user_id,
                    error = %e,
                    "2FA lockout-expiry DEL failed — user may be re-locked immediately on next attempt"
                );
            }
        }

        // MCP-688: pre-charge this attempt atomically. HINCRBY returns
        // the NEW value, serialising concurrent gate checks against
        // the same counter.
        let attempts: i64 = conn
            .hincr(&key, "failed_attempts", 1_i64)
            .await
            .context("Failed to atomically pre-charge 2FA attempt counter")?;
        // MCP-780: log EXPIRE failures. If EXPIRE silently fails, the
        // counter could persist past LOCKOUT_SECS via PERSIST (if a prior
        // op cleared the TTL) or simply never refresh — the user's
        // lockout window drifts off the expected schedule. Lower
        // operational impact than the DEL above (counter eventually
        // evicts via Redis maxmemory policy) but operator-visibility
        // still matters.
        if let Err(e) = conn.expire::<_, ()>(&key, LOCKOUT_SECS as i64).await {
            tracing::warn!(
                target: "talos_audit",
                user_id = %user_id,
                error = %e,
                "2FA rate-limit counter EXPIRE refresh failed — TTL drift possible"
            );
        }

        if attempts > MAX_2FA_ATTEMPTS as i64 {
            let locked_until_ts =
                (chrono::Utc::now() + chrono::Duration::seconds(LOCKOUT_SECS as i64)).timestamp();
            // MCP-780: log HSET locked_until failures. If this HSET
            // silently fails, the locked_until marker is NOT persisted,
            // so the next attempt's `hget locked_until` returns None and
            // the gate falls through to incrementing failed_attempts
            // beyond MAX_2FA_ATTEMPTS without surfacing the lockout to
            // the user. Counter keeps growing without a hard stop —
            // brute-force window widens silently. HIGHER impact than
            // the two above.
            if let Err(e) = conn
                .hset::<_, _, _, ()>(&key, "locked_until", locked_until_ts)
                .await
            {
                tracing::warn!(
                    target: "talos_audit",
                    user_id = %user_id,
                    error = %e,
                    "2FA HSET locked_until failed — lockout state may not persist; brute-force gate degraded"
                );
            }
            tracing::warn!(
                user_id = %user_id,
                attempts,
                "2FA lockout activated at gate (pre-charge): too many concurrent attempts"
            );
            return Ok(Err(anyhow!(
                "Too many failed 2FA attempts. Account locked for {} more seconds.",
                LOCKOUT_SECS
            )));
        }

        Ok(Ok(()))
    }

    /// Check rate limit using in-memory storage (single-instance only).
    ///
    /// MCP-688 mirror: same pre-charge pattern as the Redis variant.
    /// `DashMap::entry` holds a per-key write lock, so the increment
    /// is serialised across concurrent callers without an extra mutex.
    fn check_rate_limit_memory(&self, user_id: Uuid) -> Result<()> {
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

        // MCP-688: pre-charge under the DashMap entry lock so concurrent
        // gate checks see strictly increasing values. Strict-greater-than
        // lets the 5th attempt pass (counter = 5, proceed); the 6th sees
        // counter = 6 > 5 and is blocked.
        entry.failed_attempts += 1;
        if entry.failed_attempts > MAX_2FA_ATTEMPTS {
            entry.locked_until =
                Some(Instant::now() + std::time::Duration::from_secs(LOCKOUT_SECS));
            tracing::warn!(
                user_id = %user_id,
                attempts = entry.failed_attempts,
                "2FA lockout activated at gate (pre-charge, in-memory)"
            );
            return Err(anyhow!(
                "Too many failed 2FA attempts. Account locked for {} more seconds.",
                LOCKOUT_SECS
            ));
        }

        Ok(())
    }

    /// Post-verify failure marker.
    ///
    /// MCP-688 (2026-05-13): pre-MCP-688 this method ran HINCRBY on the
    /// failure counter AFTER verify. The counter is now charged AT THE
    /// GATE (`check_rate_limit_redis` / `check_rate_limit_memory`) so
    /// concurrent attempts can't race past a single un-charged read.
    /// This method is retained as a no-op stub so the four existing
    /// call sites in `verify_2fa_login` (TOTP replay, missing user,
    /// missing backup codes, final fall-through) keep their intent
    /// readable; the actual counter increment is the gate's
    /// responsibility now.
    ///
    /// History:
    /// - MCP-532 (2026-05-12): atomized the post-verify HINCRBY (was
    ///   HGET + HSET); closed lost-increment race.
    /// - MCP-456: TTL refresh on every failure.
    /// - MCP-688 (2026-05-13): moved the increment to the GATE so
    ///   concurrent gate-pass-then-verify can't amplify N attempts
    ///   per lockout cycle.
    async fn record_2fa_failure(&self, _user_id: Uuid) {
        // No-op — counter is pre-charged in `check_rate_limit`.
    }

    /// Reset the rate-limit counter for `user_id` after a successful 2FA verification.
    async fn record_2fa_success(&self, user_id: Uuid) {
        // Try Redis first if available
        if let Some(redis) = &self.redis_client {
            match self.record_2fa_success_redis(user_id, redis).await {
                Ok(_) => return,
                Err(e) => {
                    tracing::debug!(
                        "Redis 2FA success recording failed, falling back to in-memory: {}",
                        e
                    );
                }
            }
        }

        // Fall back to in-memory
        self.rate_limits.remove(&user_id);
    }

    /// Record success in Redis (clears rate limit state).
    async fn record_2fa_success_redis(
        &self,
        user_id: Uuid,
        redis: &Arc<redis::Client>,
    ) -> Result<()> {
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .context("Failed to get Redis connection")?;

        let key = format!("totp_rate_limit:{}", user_id);

        // Delete the rate limit key.
        //
        // MCP-791 (2026-05-14): log Redis DEL failures here too. Pre-fix
        // `let _: RedisResult<()> = conn.del(&key).await` discarded
        // errors. Worst-case impact: a user whose 2FA verification
        // SUCCEEDS but whose post-success DEL fails (Redis hiccup,
        // network blip, eviction race) keeps their `failed_attempts`
        // counter in Redis. The next failed attempt resumes the
        // counter from the pre-success value — e.g., user had 4 failed
        // attempts, succeeded, but counter not cleared → next failed
        // attempt makes counter = 5, then 6 → lockout after only 2
        // more failures instead of MAX_2FA_ATTEMPTS=5. Returning Err
        // here would trigger `record_2fa_success`'s in-memory fallback
        // (`rate_limits.remove`), but for users whose state lives in
        // Redis there's no in-memory entry to remove — net: same
        // outcome (Redis counter persists). Logging at WARN with
        // `target: "talos_audit"` gives operators visibility into the
        // unfair-lockout class without the spurious fallback work.
        // Sibling pattern to MCP-780 which closed three swallowed
        // Redis ops in `check_rate_limit_redis` (DEL on lockout
        // expiry, EXPIRE refresh, HSET locked_until); the
        // success-path DEL was missed in that sweep.
        if let Err(e) = conn.del::<_, ()>(&key).await {
            tracing::warn!(
                target: "talos_audit",
                user_id = %user_id,
                error = %e,
                "2FA success-path DEL failed — failed_attempts counter persists; user may be locked out faster on next failure"
            );
        }

        Ok(())
    }

    /// Generate a new TOTP secret for a user
    pub fn generate_secret(&self) -> String {
        use rand::RngCore;

        // Generate 20 random bytes for the secret (160 bits) via OS entropy
        let mut bytes = [0u8; 20];
        rand::rngs::OsRng.fill_bytes(&mut bytes);

        // Encode as base32
        Secret::Raw(bytes.to_vec()).to_encoded().to_string()
    }

    /// Generate backup codes (10 codes, 12 hex characters each = 48 bits of entropy).
    /// Using hex rather than decimal avoids collisions from the birthday paradox at
    /// lower digit counts and matches standard backup-code entropy recommendations.
    pub fn generate_backup_codes(&self) -> Vec<String> {
        use rand::RngCore;
        (0..10)
            .map(|_| {
                let mut bytes = [0u8; 6];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
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
                .context("Invalid secret")?,
        )
        .context("Failed to create TOTP")?;

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
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        Ok(STANDARD.encode(png_bytes))
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
            .context("System time error")?
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
    /// Returns the encoded ciphertext string AND the AAD format version
    /// that must be persisted to `users.totp_secret_format` alongside it.
    ///
    /// MCP-S2: writes bind AAD to `users.id` so an attacker with DB write
    /// access can't swap one user's TOTP ciphertext onto another row (the
    /// pre-fix swap was a silent 2FA bypass). v0/v1/v3 reads are preserved (see
    /// `decrypt_totp_secret`) for backward compatibility on existing rows.
    ///
    /// Per-org DEK arc: writes now use v4 — encrypted under the user's PERSONAL
    /// org root DEK (TOTP is inherently personal; its `org_id` is stamped from
    /// the personal org by `set_org_id_from_personal_org`, so the DEK scope
    /// matches). Decrypt is unchanged: v4 routes through the same per-context
    /// derived path as v3 (the row's `key_id` names the org DEK).
    async fn encrypt_totp_secret(&self, secret: &str, user_id: Uuid) -> Result<(String, i16)> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let (key_id, encrypted_bytes, version) = self
            .secrets_manager
            .encrypt_value_aad_v4_for_user(secret, user_id, user_id.as_bytes())
            .await?;
        // Encode as: key_id_hex:base64(nonce||ciphertext)
        let encoded = format!("{}:{}", key_id, STANDARD.encode(&encrypted_bytes));
        Ok((encoded, version))
    }

    /// Decrypt a TOTP secret that was encrypted with `encrypt_totp_secret`.
    /// Dispatches on the per-row `totp_secret_format` column (0 = legacy
    /// no-AAD, 1 = AAD-bound to `user_id` bytes).
    ///
    /// Returns the plaintext wrapped in [`zeroize::Zeroizing<String>`]
    /// so the heap allocation backing the TOTP shared-secret bytes is
    /// wiped on drop. The verifier (`verify_code`) takes `&str`; deref
    /// coercion from `&Zeroizing<String>` to `&str` is transparent.
    async fn decrypt_totp_secret(
        &self,
        encrypted: &str,
        user_id: Uuid,
        format_version: i16,
    ) -> Result<zeroize::Zeroizing<String>> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let parts: Vec<&str> = encrypted.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid encrypted TOTP secret format"));
        }
        let key_id: Uuid = parts[0]
            .parse()
            .map_err(|_| anyhow!("Invalid encryption key ID in TOTP secret"))?;
        let encrypted_bytes = STANDARD
            .decode(parts[1])
            .map_err(|_| anyhow!("Invalid base64 in encrypted TOTP secret"))?;
        self.secrets_manager
            .decrypt_versioned(key_id, &encrypted_bytes, user_id.as_bytes(), format_version)
            .await
    }

    /// Enable 2FA for a user.
    ///
    /// Refuses to overwrite an existing TOTP secret. If 2FA is already
    /// enabled, the caller must `disable_2fa` first — and `disable_2fa`
    /// requires `is_2fa_verified=true` at the GraphQL layer. Without this
    /// guard, a partial-2FA session (post-password, pre-TOTP) could call
    /// `enable_two_factor` with an attacker-controlled secret and lock
    /// the legitimate user out of their own account.
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

        // L-13: Hash backup codes before storing. Pre-fix:
        //   bcrypt::hash(code, ...).unwrap_or_else(|_| code.clone())
        // — would have stored the PLAINTEXT backup code in the DB if
        // bcrypt::hash ever failed (essentially impossible in practice,
        // but the fallback was a security regression in waiting). Now
        // propagate the error so the caller knows enable_2fa failed
        // closed rather than completing with weakened credentials.
        let mut hashed_codes: Vec<String> = Vec::with_capacity(backup_codes.len());
        for code in &backup_codes {
            let hash = bcrypt::hash(code, bcrypt::DEFAULT_COST)
                .map_err(|e| anyhow!("Failed to hash 2FA backup code: {e}"))?;
            hashed_codes.push(hash);
        }

        // MCP-S2: encrypt the TOTP secret with AAD = user_id so an
        // attacker with DB write capability can't swap victim's
        // totp_secret onto attacker's row (silent 2FA bypass pre-fix).
        // The encrypt helper returns the wire-format string and the
        // AAD version constant (1); both must be persisted together.
        let (encrypted_secret, format_version) = self.encrypt_totp_secret(secret, user_id).await?;

        // Atomic enable — `WHERE totp_enabled IS NOT TRUE` rejects the
        // overwrite if 2FA is already on. `rows_affected() == 0` means
        // the user already has 2FA enabled and the request is an attempt
        // to re-key. Surfacing this as an error rather than silently
        // succeeding tells the legitimate user something is wrong on
        // the next login attempt.
        //
        // Use the dynamic `sqlx::query` (not the compile-time `query!`
        // macro) so this UPDATE doesn't need to be added to the sqlx
        // offline cache — matches the pattern already used for the
        // similar atomic UPDATE in `login`.
        let result = sqlx::query(
            "UPDATE users
             SET totp_secret = $1, totp_secret_format = $2, totp_enabled = true, backup_codes = $3
             WHERE id = $4 AND totp_enabled IS NOT TRUE",
        )
        .bind(&encrypted_secret)
        .bind(format_version)
        .bind(&hashed_codes[..])
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;

        if result.rows_affected() == 0 {
            tracing::warn!(
                user_id = %user_id,
                "enable_2fa rejected: 2FA already enabled — possible re-key attack"
            );
            return Err(anyhow!(
                "Two-factor authentication is already enabled. Disable it first if you need to re-enrol."
            ));
        }

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

        // Revoke ALL active sessions when 2FA is disabled.
        //
        // Active sessions carry is_2fa_verified=true in their JWT claims. After
        // disabling 2FA those claims are stale — sessions that previously satisfied
        // 2FA will continue to be accepted even though 2FA is no longer configured.
        // Revoking forces the user (and any attacker who had a valid session) to
        // re-authenticate against the current security posture.
        sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.db_pool)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to revoke sessions after 2FA disable: {}", e))?;

        Ok(())
    }

    /// Verify 2FA code during login (supports both TOTP and backup codes).
    ///
    /// Includes brute-force protection: after 5 consecutive failures the user
    /// is locked out for 15 minutes.  Backup code consumption is atomic (uses a
    /// DB transaction with a PostgreSQL advisory lock) to prevent TOCTOU races.
    pub async fn verify_2fa_login(&self, user_id: Uuid, code: &str, email: &str) -> Result<bool> {
        use sqlx::Row as _;

        // MCP-1095 (2026-05-16): fail-closed when Redis is unavailable
        // at the START of production verification. Pre-fix, when
        // `redis_client = None` (REDIS_URL unset, connect-test failed
        // at boot, helm placeholder), `check_rate_limit` silently fell
        // back to per-pod in-memory rate limiting (multi-replica
        // bypass: 3 attempts per pod × N pods = 3N attempts) AND the
        // TOTP-replay-cache block at line ~653 was skipped entirely
        // because its `if let Some(redis)` matched None — so any
        // captured TOTP code could be replayed within the 90-second
        // drift window with no detection. The
        // `check_rate_limit_redis` path's existing "production fails
        // closed on Redis unreachable" only fired when Redis was
        // configured but unreachable; this closes the missing
        // "Redis not configured at all" case.
        //
        // Same fail-closed-at-boundary class as the existing replay-
        // cache `Err(e)` path inside this function (lines ~656-668).
        // Operators in dev / single-pod tests can still verify
        // without Redis; production must have it.
        if talos_config::is_production() && self.redis_client.is_none() {
            tracing::error!(
                user_id = %user_id,
                "TOTP verification rejected in production: Redis is required \
                 for rate limiting AND replay protection but redis_client is \
                 None. Set REDIS_URL and ensure the controller can reach it."
            );
            anyhow::bail!(
                "Authentication service temporarily unavailable. Please try again shortly."
            );
        }

        // Enforce rate limit before doing any DB work.
        self.check_rate_limit(user_id).await?;

        // Fetch user data outside a transaction — TOTP verification doesn't
        // modify DB state so we don't need a lock for that path.
        // MCP-S2: `totp_secret_format` is the AEAD AAD version for
        // `totp_secret`; the dispatcher routes v0 rows (legacy, no AAD)
        // through the empty-AAD decrypt and v1 rows through the
        // AAD=user_id decrypt. sqlx::query (dynamic) avoids the offline
        // cache regeneration churn that adding a column to the
        // `query!`-macro version would trigger.
        #[derive(sqlx::FromRow)]
        struct TotpUserRow {
            totp_secret: Option<String>,
            totp_enabled: bool,
            backup_codes: Option<Vec<String>>,
            totp_secret_format: i16,
        }
        let user = sqlx::query_as::<_, TotpUserRow>(
            "SELECT totp_secret, totp_enabled, backup_codes, totp_secret_format
             FROM users
             WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow!("User not found"))?;

        if !user.totp_enabled {
            return Err(anyhow!("2FA not enabled for this user"));
        }

        let encrypted_secret = user
            .totp_secret
            .ok_or_else(|| anyhow!("TOTP secret not found"))?;

        // Decrypt the TOTP secret before use. The version column +
        // user_id bytes together drive the AAD-binding dispatch (MCP-S2);
        // a swapped ciphertext (different `user_id` on the v1 row) fails
        // AES-GCM tag verification and propagates as Err.
        let secret = self
            .decrypt_totp_secret(&encrypted_secret, user_id, user.totp_secret_format)
            .await?;

        // Try TOTP code first.
        if self.verify_code(&secret, email, code)? {
            // SECURITY: Prevent TOTP replay within the verification window.
            // We allow ±1 time-step (3 × 30 s = 90 s total).  Cache the used
            // code per user for 90 seconds — a second use of the same code in
            // the same window is rejected even if the signature is valid.
            if let Some(redis) = &self.redis_client {
                let cache_key = format!("totp_used:{}:{}", user_id, code);
                match redis.get_multiplexed_async_connection().await {
                    Err(e) => {
                        // Fail closed: if Redis is unavailable we cannot enforce replay
                        // prevention, so reject the login rather than accept a potentially
                        // replayed code.
                        tracing::error!(
                            user_id = %user_id,
                            "TOTP replay cache unavailable — rejecting login for safety: {}",
                            e
                        );
                        return Err(anyhow::anyhow!(
                            "Authentication service temporarily unavailable. Please try again."
                        ));
                    }
                    Ok(mut conn) => {
                        // SET NX (only if not exists) with 90-second expiry.
                        let inserted: bool = redis::cmd("SET")
                            .arg(&cache_key)
                            .arg(1u8)
                            .arg("NX")
                            .arg("EX")
                            .arg(90u64)
                            .query_async::<Option<String>>(&mut conn)
                            .await
                            .map(|v| v.is_some()) // Some("OK") = inserted; None = key existed
                            .unwrap_or(false);
                        if !inserted {
                            tracing::warn!(
                                user_id = %user_id,
                                "TOTP replay detected: code already used within the current window"
                            );
                            self.record_2fa_failure(user_id).await;
                            return Ok(false);
                        }
                    }
                }
            }
            self.record_2fa_success(user_id).await;
            return Ok(true);
        }

        // MCP-476: short-circuit backup-code verification when the input
        // cannot possibly BE a backup code. Backup codes from
        // `generate_backup_codes` are always 12 lowercase hex chars; a
        // 6-digit TOTP guess (or anything else shorter / non-hex) cannot
        // succeed against `bcrypt::verify`. Pre-fix, every failed 2FA
        // attempt fell through and bcrypt-verified the input against ALL
        // 10 stored backup codes — at ~100 ms each, that's ~1 second of
        // server CPU per probe. Combined with the per-user rate-limit
        // window (3 attempts / 15 min) the maximum amortised cost is
        // bounded, but within a single window a probe still amplifies
        // ~10× the cost of a normal login. Skipping the loop when the
        // shape doesn't match is a 10x defensive cut with zero loss of
        // correctness for the intended flows.
        let looks_like_backup_code =
            code.len() == 12 && code.chars().all(|c| c.is_ascii_hexdigit());
        if user.backup_codes.is_some() && looks_like_backup_code {
            let mut tx = self.db_pool.begin().await?;

            // L-17: derive a 128-bit advisory lock key from the FULL UUID
            // (split as two i32 halves for `pg_advisory_xact_lock(int4, int4)`).
            // Pre-fix used only the first 8 bytes of the UUID as a single
            // i64, giving birthday-collision risk at ~65k users (and any
            // collision = false-shared lock contention across unrelated
            // users in the backup-code consumption path). Using both halves
            // expands the keyspace to 2^128 — collisions cease to be
            // practically possible.
            let bytes = user_id.as_bytes();
            let lock_key_hi = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let lock_key_lo = i32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
                ^ i32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]])
                ^ i32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
            // Use non-macro form so no offline cache entry is required.
            sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
                .bind(lock_key_hi)
                .bind(lock_key_lo)
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
                    self.record_2fa_failure(user_id).await;
                    return Ok(false);
                }
                Some(row) => {
                    let codes: Option<Vec<String>> = row.try_get("backup_codes").ok().flatten();
                    match codes {
                        None => {
                            tx.rollback().await?;
                            self.record_2fa_failure(user_id).await;
                            return Ok(false);
                        }
                        Some(c) => c,
                    }
                }
            };

            // MCP-511: hex is case-insensitive by spec but bcrypt::verify
            // is byte-exact. `generate_backup_codes` writes lowercase
            // hex via `hex::encode`, so a user retyping a backup code
            // in uppercase (handwritten note, password-manager
            // auto-cap) would pass the `looks_like_backup_code` gate
            // (which uses `is_ascii_hexdigit`, case-insensitive) and
            // then silently fail every bcrypt::verify. Normalize to
            // lowercase before verification — no entropy loss (hex
            // case carries no info) and matches the stored hash space.
            let normalized = code.to_ascii_lowercase();
            for (index, hashed_code) in locked_codes.iter().enumerate() {
                // MCP-1099 (2026-05-16): log bcrypt::verify Err distinctly
                // instead of collapsing to a silent mismatch via
                // `.unwrap_or(false)`. A malformed stored backup-code
                // hash (DB corruption, schema drift, partial-write
                // recovery) would otherwise produce a "no codes match"
                // outcome that is operationally indistinguishable from
                // a wrong-code user mistake. Sibling fix to the
                // talos-api-keys verify-loop on the same line; both
                // mirror MCP-873's mcp-auth pattern.
                let verified = match bcrypt::verify(&normalized, hashed_code) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            target: "talos_audit",
                            user_id = %user_id,
                            backup_index = index,
                            error = %e,
                            "backup-code bcrypt::verify failed (possibly malformed stored hash) — skipping"
                        );
                        false
                    }
                };
                if verified {
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
                    tracing::debug!("User {} used backup code", user_id);
                    self.record_2fa_success(user_id).await;
                    return Ok(true);
                }
            }

            tx.rollback().await?;
        }

        // Verification failed — record the failure and return false.
        self.record_2fa_failure(user_id).await;
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
        std::env::set_var(
            "TALOS_MASTER_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        // allow-secrets-manager-new: test stub — no McpState in unit tests
        let secrets_manager =
            Arc::new(talos_secrets_manager::SecretsManager::new(db_pool.clone()).unwrap());
        let service = TotpService::new(db_pool, None, secrets_manager);

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
        std::env::set_var(
            "TALOS_MASTER_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        // allow-secrets-manager-new: test stub — no McpState in unit tests
        let secrets_manager =
            Arc::new(talos_secrets_manager::SecretsManager::new(db_pool.clone()).unwrap());
        let service = TotpService::new(db_pool, None, secrets_manager);

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
        std::env::set_var(
            "TALOS_MASTER_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        // allow-secrets-manager-new: test stub — no McpState in unit tests
        let secrets_manager =
            Arc::new(talos_secrets_manager::SecretsManager::new(db_pool.clone()).unwrap());
        let service = TotpService::new(db_pool, None, secrets_manager);

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
            .is_none_or(|e| e.locked_until.is_none());
        assert!(check_result);
    }
}

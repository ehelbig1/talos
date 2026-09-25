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

/// Enrolment attempts (`setupTwoFactor` + `enableTwoFactor`) one user may make
/// per [`ENROLMENT_WINDOW_SECS`]. A person enrolling needs two or three. The
/// bound is on cost, not guessing: an enable hashes ten backup codes with
/// bcrypt, and nothing else stopped a signed-in caller from enabling and
/// disabling in a loop.
pub const MAX_ENROLMENT_ATTEMPTS: u32 = 10;
/// Length of the fixed enrolment-throttle window.
const ENROLMENT_WINDOW_SECS: u64 = 900; // 15 minutes
/// Above this many tracked users the in-memory throttle drops expired windows
/// before adding one, so the map cannot grow without bound.
const MAX_TRACKED_ENROLMENT_WINDOWS: usize = 10_000;

/// The caller-facing sentence for [`EnrolmentThrottled`].
pub const ENROLMENT_THROTTLED_MESSAGE: &str =
    "Too many two-factor setup attempts. Please try again in 15 minutes.";

/// A user made more than [`MAX_ENROLMENT_ATTEMPTS`] enrolment attempts in the
/// current window. Carried inside `anyhow::Error` by `enable_2fa`, so a caller
/// can recognise it with `downcast_ref` and show its message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrolmentThrottled;

impl std::fmt::Display for EnrolmentThrottled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(ENROLMENT_THROTTLED_MESSAGE)
    }
}

impl std::error::Error for EnrolmentThrottled {}

/// One user's in-memory enrolment window.
#[derive(Debug)]
struct EnrolmentWindow {
    attempts: u32,
    started: Instant,
}

/// 2FA/TOTP service
pub struct TotpService {
    db_pool: Pool<Postgres>,
    issuer: String,
    redis_client: Option<Arc<redis::Client>>,
    rate_limits: Arc<DashMap<Uuid, TotpRateState>>,
    enrolment_windows: Arc<DashMap<Uuid, EnrolmentWindow>>,
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
            enrolment_windows: Arc::new(DashMap::new()),
            secrets_manager,
        }
    }

    /// Charge one enrolment attempt to `user_id` and refuse past
    /// [`MAX_ENROLMENT_ATTEMPTS`] per window. `enable_2fa` calls it; the
    /// `setupTwoFactor` resolver calls it before generating a secret, so both
    /// steps share one budget.
    ///
    /// Redis when configured, so the budget holds across replicas. When Redis
    /// is absent or failing the attempt is charged to this process's window
    /// instead, in production too: this bounds CPU, not guessing (the caller
    /// chooses the secret), so a per-replica bound is still a bound, whereas
    /// refusing would block enrolment on a Redis outage.
    pub async fn check_enrolment_throttle(
        &self,
        user_id: Uuid,
    ) -> std::result::Result<(), EnrolmentThrottled> {
        let attempts = match &self.redis_client {
            Some(redis) => match self.charge_enrolment_redis(user_id, redis).await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!(
                        user_id = %user_id,
                        "2FA enrolment throttle: Redis unavailable, charging this \
                         replica's in-memory window instead: {e:#}"
                    );
                    u64::from(self.charge_enrolment_memory(user_id, Instant::now()))
                }
            },
            None => u64::from(self.charge_enrolment_memory(user_id, Instant::now())),
        };
        if attempts > u64::from(MAX_ENROLMENT_ATTEMPTS) {
            tracing::info!(
                target: "talos_audit",
                event_kind = "2fa_enrolment_throttled",
                user_id = %user_id,
                attempts,
                "2FA enrolment attempt refused: too many attempts in the window"
            );
            return Err(EnrolmentThrottled);
        }
        Ok(())
    }

    /// One atomic MULTI: create the window key with its TTL if absent, then
    /// count this attempt. The TTL is set only by the `SET NX`, so the window
    /// is fixed from the first attempt and cannot be left without an expiry.
    async fn charge_enrolment_redis(&self, user_id: Uuid, redis: &redis::Client) -> Result<u64> {
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .context("Failed to get Redis connection")?;
        let key = format!("totp_enrol:{user_id}");
        let (attempts,): (u64,) = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(&key)
            .arg(0u8)
            .arg("NX")
            .arg("EX")
            .arg(ENROLMENT_WINDOW_SECS)
            .ignore()
            .cmd("INCR")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .context("Failed to charge the 2FA enrolment window")?;
        Ok(attempts)
    }

    /// The in-memory window: fixed from its first attempt, restarted once it
    /// has run [`ENROLMENT_WINDOW_SECS`]. `now` is a parameter so a test can
    /// move past the window without subtracting from an `Instant`.
    fn charge_enrolment_memory(&self, user_id: Uuid, now: Instant) -> u32 {
        let window = std::time::Duration::from_secs(ENROLMENT_WINDOW_SECS);
        if self.enrolment_windows.len() > MAX_TRACKED_ENROLMENT_WINDOWS {
            self.enrolment_windows
                .retain(|_, w| now.duration_since(w.started) < window);
        }
        let mut entry = self
            .enrolment_windows
            .entry(user_id)
            .or_insert_with(|| EnrolmentWindow {
                attempts: 0,
                started: now,
            });
        if now.duration_since(entry.started) >= window {
            entry.attempts = 0;
            entry.started = now;
        }
        entry.attempts = entry.attempts.saturating_add(1);
        entry.attempts
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

        // Check if user is currently locked out.
        //
        // #661 (error-as-absence): this read must propagate. `.ok()` made a
        // failed HGET read as "not locked" — the identical state MCP-780's
        // comment below describes as the degraded outcome of a failed HSET
        // ("the next attempt's `hget locked_until` returns None and the gate
        // falls through ... brute-force gate degraded"). Three Redis ops in
        // this function (DEL, EXPIRE, HSET) log their failures with that
        // impact spelled out; the one op that DECIDES whether the user is
        // locked out was the only one that swallowed silently. The HINCRBY
        // pre-charge below still backstops the counter, so this is a
        // defense-in-depth gate rather than the sole one — but a lockout
        // skipped because Redis hiccuped is indistinguishable from a user who
        // was never locked, and that is exactly what this class costs.
        let locked_until: Option<i64> = conn
            .hget(&key, "locked_until")
            .await
            .context("Failed to read 2FA lockout state")?;

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
        // The rate-limit counter is pre-charged in `check_rate_limit`; what
        // happens here is the METRIC. Every failing verification path (TOTP
        // mismatch, replay, bad backup code) calls this, so it is the ONE
        // place `talos_auth_2fa_attempts_total{status="failure"}` moves —
        // registered 2026-05, first incremented 2026-09-11.
        talos_metrics::record_2fa_attempt(talos_metrics::TwoFactorOutcome::Failure);
    }

    /// Reset the rate-limit counter for `user_id` after a successful 2FA verification.
    async fn record_2fa_success(&self, user_id: Uuid) {
        talos_metrics::record_2fa_attempt(talos_metrics::TwoFactorOutcome::Success);
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
    ///
    /// AAD is DOMAIN-TAGGED (2026-09-10): `aad_for(TOTP_SECRET_TAG, user_id)`
    /// = `b"totp\0" || user_id`, not the bare `user_id`. With the bare id,
    /// this column and `user_audit_settings.auth_headers_encrypted` (also
    /// AAD = bare `user_id`) derived the SAME per-context subkey for one
    /// user, so a TOTP blob was a valid ciphertext for the header column and
    /// vice versa — the swap failed only at the JSON parse. The tag lives in
    /// `talos_secrets_manager::aad` (one home). Rows written before the tag
    /// still decrypt via the bare-id fallback in `decrypt_totp_secret` and
    /// are moved onto the tagged context by the next enrol — no sweep.
    async fn encrypt_totp_secret(&self, secret: &str, user_id: Uuid) -> Result<(String, i16)> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let aad = talos_secrets_manager::aad::aad_for(
            talos_secrets_manager::aad::TOTP_SECRET_TAG,
            user_id,
        );
        let (key_id, encrypted_bytes, version) = self
            .secrets_manager
            .encrypt_value_aad_v4_for_user(secret, user_id, &aad)
            .await?;
        // Encode as: key_id_hex:base64(nonce||ciphertext)
        let encoded = format!("{}:{}", key_id, STANDARD.encode(&encrypted_bytes));
        Ok((encoded, version))
    }

    /// Decrypt a TOTP secret that was encrypted with `encrypt_totp_secret`.
    /// Dispatches on the per-row `totp_secret_format` column (0 = legacy
    /// no-AAD; 1/3/4 = AAD-bound), trying the domain-tagged AAD first and
    /// falling back to the pre-tag bare `user_id` AAD for existing rows
    /// (`SecretsManager::decrypt_versioned_tagged`). Which path opened the
    /// row is logged at DEBUG only; a legacy row is never failed.
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
        // `decrypt_versioned_tagged` returns `Result<_, SecretsError>`; this
        // method's contract is `anyhow::Result`, so map into anyhow.
        let (plaintext, aad_path) = self
            .secrets_manager
            .decrypt_versioned_tagged(
                key_id,
                &encrypted_bytes,
                talos_secrets_manager::aad::TOTP_SECRET_TAG,
                user_id,
                format_version,
            )
            .await?;
        tracing::debug!(
            user_id = %user_id,
            aad_path = aad_path.as_str(),
            format_version,
            "TOTP secret decrypted"
        );
        Ok(plaintext)
    }

    /// Enable 2FA for a user.
    ///
    /// Refuses to overwrite an existing TOTP secret. If 2FA is already
    /// enabled, the caller must `disable_2fa` first — and `disable_2fa`
    /// requires `is_2fa_verified=true` at the GraphQL layer. Without this
    /// guard, a partial-2FA session (post-password, pre-TOTP) could call
    /// `enable_two_factor` with an attacker-controlled secret and lock
    /// the legitimate user out of their own account.
    ///
    /// Order (2026-09-25): the enrolment throttle, then the already-enabled
    /// refusal, then the code — all before any of the ten bcrypt hashes, which
    /// run on the blocking pool. Before, the hashes ran first and inline on the
    /// async runtime thread (measured: the thread blocked 6.0 s of a 6.1 s
    /// enrolment in a debug build), so every refused re-enrolment still paid
    /// for all ten and stalled that thread.
    /// The `WHERE totp_enabled IS NOT TRUE` guard on the write stays: the early
    /// read is not atomic with it.
    pub async fn enable_2fa(
        &self,
        user_id: Uuid,
        secret: &str,
        verification_code: &str,
        email: &str,
    ) -> Result<Vec<String>> {
        self.check_enrolment_throttle(user_id).await?;

        let enabled: Option<Option<bool>> =
            sqlx::query_scalar("SELECT totp_enabled FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        match enabled {
            None => return Err(anyhow!("User not found")),
            Some(Some(true)) => return Err(already_enabled_refusal(user_id)),
            Some(_) => {}
        }

        if !self.verify_code(secret, email, verification_code)? {
            return Err(anyhow!("Invalid verification code"));
        }

        // Generate backup codes
        let backup_codes = self.generate_backup_codes();

        // L-13: a hash failure fails the enable; a plaintext backup code is
        // never stored.
        let hashed_codes = hash_backup_codes(&backup_codes).await?;

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
        //
        // The enrolment and its `2fa_enabled` record in `admin_event_log`
        // commit in ONE transaction (2026-09-18 — the record used to be a
        // detached task in the resolver after the enrolment had committed).
        let mut tx = self.db_pool.begin().await?;
        let result = sqlx::query(
            "UPDATE users
             SET totp_secret = $1, totp_secret_format = $2, totp_enabled = true, backup_codes = $3
             WHERE id = $4 AND totp_enabled IS NOT TRUE",
        )
        .bind(&encrypted_secret)
        .bind(format_version)
        .bind(&hashed_codes[..])
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err(already_enabled_refusal(user_id));
        }
        talos_admin_event_log::insert_on_conn(
            &mut tx,
            Some(user_id),
            "2fa_enabled",
            "user",
            Some(user_id),
            "Two-factor authentication enabled",
            None,
        )
        .await?;
        tx.commit().await?;

        // Return plain backup codes to user (only shown once!)
        Ok(backup_codes)
    }

    /// Disable 2FA for a user.
    ///
    /// The disable, the revocation of every session and the `2fa_disabled`
    /// record in `admin_event_log` commit in ONE transaction (2026-09-18).
    /// Before, they were three separate writes: a failed session DELETE left
    /// 2FA off with the old sessions alive, and the record was a detached
    /// task in the resolver.
    pub async fn disable_2fa(&self, user_id: Uuid) -> Result<()> {
        let mut tx = self.db_pool.begin().await?;
        sqlx::query!(
            "UPDATE users
             SET totp_secret = NULL, totp_enabled = false, backup_codes = NULL
             WHERE id = $1",
            user_id
        )
        .execute(&mut *tx)
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
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to revoke sessions after 2FA disable: {}", e))?;

        talos_admin_event_log::insert_on_conn(
            &mut tx,
            Some(user_id),
            "2fa_disabled",
            "user",
            Some(user_id),
            "Two-factor authentication disabled",
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Verify 2FA code during login (supports both TOTP and backup codes).
    ///
    /// Includes brute-force protection: after 5 consecutive failures the user
    /// is locked out for 15 minutes. Backup-code consumption is atomic: one
    /// conditional `UPDATE` removes the matched hash only if it is still
    /// stored, so a code cannot be spent twice.
    pub async fn verify_2fa_login(&self, user_id: Uuid, code: &str, email: &str) -> Result<bool> {
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
        if let (Some(stored), true) = (user.backup_codes, looks_like_backup_code) {
            // MCP-511: hex is case-insensitive but bcrypt::verify is
            // byte-exact, and `generate_backup_codes` writes lowercase.
            let candidate = code.to_ascii_lowercase();
            // Up to ten bcrypt verifies: on the blocking pool, and before any
            // transaction or lock is taken (2026-09-25 — they used to run
            // inline on the async runtime thread, inside a transaction holding
            // this user's advisory lock).
            if let Some(matched) = find_backup_code(user_id, candidate, stored).await? {
                // Spend it atomically: the hash is removed only if it is still
                // there, so of two concurrent uses of one code exactly one
                // UPDATE changes a row. The hashes are salted, so the stored
                // string identifies this one code.
                let consumed = sqlx::query(
                    "UPDATE users SET backup_codes = array_remove(backup_codes, $1) \
                     WHERE id = $2 AND $1 = ANY(backup_codes)",
                )
                .bind(&matched)
                .bind(user_id)
                .execute(&self.db_pool)
                .await?
                .rows_affected();
                if consumed == 1 {
                    tracing::debug!("User {} used backup code", user_id);
                    self.record_2fa_success(user_id).await;
                    return Ok(true);
                }
                tracing::warn!(
                    target: "talos_audit",
                    user_id = %user_id,
                    "backup code matched but was already spent by a concurrent attempt"
                );
            }
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

/// The refusal for enrolling an account that already has 2FA enabled.
fn already_enabled_refusal(user_id: Uuid) -> anyhow::Error {
    tracing::warn!(
        user_id = %user_id,
        "enable_2fa rejected: 2FA already enabled — possible re-key attack"
    );
    anyhow!(
        "Two-factor authentication is already enabled. Disable it first if you need to re-enrol."
    )
}

/// bcrypt every backup code on the blocking pool. Ten hashes at the default
/// cost are seconds of CPU; run inline they stall a runtime thread and every
/// task scheduled on it.
async fn hash_backup_codes(codes: &[String]) -> Result<Vec<String>> {
    let codes = codes.to_vec();
    tokio::task::spawn_blocking(move || {
        codes
            .iter()
            .map(|code| {
                bcrypt::hash(code, bcrypt::DEFAULT_COST)
                    .map_err(|e| anyhow!("Failed to hash 2FA backup code: {e}"))
            })
            .collect::<Result<Vec<String>>>()
    })
    .await
    .context("2FA backup-code hashing task failed")?
}

/// The stored hash `candidate` matches, if any, checked on the blocking pool.
///
/// MCP-1099: a stored hash bcrypt cannot parse is logged and skipped, never
/// collapsed silently into "no match".
async fn find_backup_code(
    user_id: Uuid,
    candidate: String,
    stored: Vec<String>,
) -> Result<Option<String>> {
    tokio::task::spawn_blocking(move || {
        for (index, hashed) in stored.into_iter().enumerate() {
            match bcrypt::verify(&candidate, &hashed) {
                Ok(true) => return Some(hashed),
                Ok(false) => {}
                Err(e) => tracing::warn!(
                    target: "talos_audit",
                    user_id = %user_id,
                    backup_index = index,
                    error = %e,
                    "backup-code bcrypt::verify failed (possibly malformed stored hash) — skipping"
                ),
            }
        }
        None
    })
    .await
    .context("2FA backup-code verification task failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `TotpService` over a never-connected lazy pool: every test here
    /// exercises the limiter, which runs before any DB work, so a touched pool
    /// would fail the test loudly rather than pass on a stub.
    pub(super) fn stub_service(redis_client: Option<Arc<redis::Client>>) -> TotpService {
        std::env::set_var(
            "TALOS_MASTER_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let db_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://127.0.0.1:1/talos_never_connects")
            .expect("lazy pool");
        // allow-secrets-manager-new: test stub — no McpState in unit tests
        let secrets_manager =
            Arc::new(talos_secrets_manager::SecretsManager::new(db_pool.clone()).unwrap());
        TotpService::new(db_pool, redis_client, secrets_manager)
    }

    /// The `qrCodePng` contract, from the producer's side: BARE base64 of a
    /// PNG — no `data:` prefix. The web UI builds the image URL from it; its
    /// test fixture once assumed a data URL, so the QR image never rendered
    /// while the test stayed green (2026-09-18).
    #[tokio::test]
    async fn qr_code_png_is_bare_base64_of_a_png() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let service = stub_service(None);
        let secret = service.generate_secret();
        let png = service
            .generate_qr_code_png(&secret, "user@example.com")
            .expect("qr code");
        assert!(!png.starts_with("data:"), "no data-URL prefix on the wire");
        let bytes = STANDARD.decode(&png).expect("valid base64");
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "PNG signature");
    }

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

    /// The DEV fallback limiter, driven through the production function
    /// rather than a re-implementation of it. The two tests this replaces
    /// rebuilt the counter arithmetic over their own `DashMap` and asserted
    /// against that copy, so the production `check_rate_limit_memory` could
    /// have been gutted with both of them green (CLAUDE.md's own
    /// "unit tests exercise real production code" rule).
    #[tokio::test]
    async fn the_memory_limiter_locks_after_max_attempts_and_a_success_clears_it() {
        let service = stub_service(None);
        let user_id = Uuid::new_v4();

        // The pre-charge admits exactly MAX_2FA_ATTEMPTS.
        for attempt in 1..=MAX_2FA_ATTEMPTS {
            service
                .check_rate_limit_memory(user_id)
                .unwrap_or_else(|e| panic!("attempt {attempt} must be admitted: {e}"));
        }
        let locked = service
            .check_rate_limit_memory(user_id)
            .expect_err("the attempt past the cap is refused");
        assert!(
            locked.to_string().contains("Too many failed 2FA attempts"),
            "{locked}"
        );

        // A second user is unaffected — the counter is per user.
        service
            .check_rate_limit_memory(Uuid::new_v4())
            .expect("another user is not locked out");

        // Success clears the counter, so the full budget is available again.
        service.rate_limits.remove(&user_id);
        for attempt in 1..=MAX_2FA_ATTEMPTS {
            service
                .check_rate_limit_memory(user_id)
                .unwrap_or_else(|e| panic!("post-success attempt {attempt}: {e}"));
        }
        service
            .check_rate_limit_memory(user_id)
            .expect_err("the cap applies again after the reset");
    }

    /// `RUST_ENV` is process-global and these tests move it, so every test
    /// whose behaviour depends on `is_production()` takes this lock.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct ProdEnv(Option<String>);
    impl ProdEnv {
        fn set() -> Self {
            let prev = std::env::var("RUST_ENV").ok();
            std::env::set_var("RUST_ENV", "production");
            Self(prev)
        }
    }
    impl Drop for ProdEnv {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var("RUST_ENV", v),
                None => std::env::remove_var("RUST_ENV"),
            }
        }
    }

    /// Production with no Redis configured at all refuses the verification
    /// before any DB work — the pool here can never connect, so a regression
    /// that let this through would surface as a pool timeout, not a refusal.
    #[tokio::test]
    async fn production_without_redis_refuses_before_the_database() {
        let _guard = ENV_LOCK.lock().await;
        let service = stub_service(None);
        let _prod = ProdEnv::set();
        let err = service
            .verify_2fa_login(Uuid::new_v4(), "000000", "user@example.com")
            .await
            .expect_err("production without Redis must refuse");
        assert!(
            err.to_string().contains("temporarily unavailable"),
            "refusal must be the fail-closed one, got: {err}"
        );
    }

    /// Redis CONFIGURED but unreachable: production refuses, development falls
    /// back to the in-memory counter (and really charges it). The two arms are
    /// one test so the control cannot drift away from the case it controls.
    #[tokio::test]
    async fn an_unreachable_redis_refuses_in_production_and_falls_back_in_development() {
        let _guard = ENV_LOCK.lock().await;
        let unreachable =
            Arc::new(redis::Client::open("redis://127.0.0.1:1").expect("client for a dead port"));
        let service = stub_service(Some(unreachable));
        let user_id = Uuid::new_v4();

        {
            let _prod = ProdEnv::set();
            let err = service
                .check_rate_limit(user_id)
                .await
                .expect_err("production must not degrade to per-process state");
            assert!(err.to_string().contains("temporarily unavailable"), "{err}");
        }
        assert!(
            service.rate_limits.is_empty(),
            "a production refusal must not seed the in-memory counter"
        );

        service
            .check_rate_limit(user_id)
            .await
            .expect("development falls back to the in-memory limiter");
        assert_eq!(
            service.rate_limits.get(&user_id).map(|e| e.failed_attempts),
            Some(1),
            "the dev fallback must charge the attempt it admitted"
        );
    }

    /// Both recorders — the ONE place every verification path lands — must
    /// count on `talos_auth_2fa_attempts_total`. A SOURCE PIN, stated as
    /// such: `verify_2fa_login` needs a user row, an encrypted TOTP secret
    /// and (in production) Redis to drive, so the recorder's own behaviour is
    /// proved in `talos-metrics` and this pins that a revert of either line
    /// is visible.
    #[test]
    fn both_2fa_recorders_count_the_attempt() {
        let src = include_str!("lib.rs");
        let failure = src
            .split("async fn record_2fa_failure(")
            .nth(1)
            .expect("failure recorder")
            .split("\n    }\n")
            .next()
            .expect("failure body");
        assert!(failure.contains("record_2fa_attempt(talos_metrics::TwoFactorOutcome::Failure)"));
        let success = src
            .split("async fn record_2fa_success(")
            .nth(1)
            .expect("success recorder")
            .split("\n    }\n")
            .next()
            .expect("success body");
        assert!(success.contains("record_2fa_attempt(talos_metrics::TwoFactorOutcome::Success)"));
        // And every verification path calls one of the two: four call sites
        // today (TOTP replay failure, TOTP success, backup-code success, and
        // the final failure every other path falls through to — the two
        // early-exit backup-code failures went with the advisory lock,
        // 2026-09-25).
        let calls = src
            .matches("self.record_2fa_failure(user_id).await")
            .count()
            + src
                .matches("self.record_2fa_success(user_id).await")
                .count();
        assert!(
            calls >= 4,
            "expected >= 4 recorder call sites, found {calls}"
        );
    }

    /// The in-memory enrolment window, which is what production falls back to
    /// without Redis: the cap passes, the next attempt is refused, another
    /// user's budget is separate, and a window that has run its length
    /// restarts. No database is touched.
    #[tokio::test]
    async fn the_in_memory_enrolment_window_bounds_each_user() {
        let service = stub_service(None);
        let (user, other) = (Uuid::new_v4(), Uuid::new_v4());
        for attempt in 1..=MAX_ENROLMENT_ATTEMPTS {
            assert_eq!(
                service.check_enrolment_throttle(user).await,
                Ok(()),
                "attempt {attempt}"
            );
        }
        assert_eq!(
            service.check_enrolment_throttle(user).await,
            Err(EnrolmentThrottled)
        );
        assert_eq!(service.check_enrolment_throttle(other).await, Ok(()));
        assert_eq!(EnrolmentThrottled.to_string(), ENROLMENT_THROTTLED_MESSAGE);

        let later = Instant::now() + std::time::Duration::from_secs(ENROLMENT_WINDOW_SECS);
        assert_eq!(service.charge_enrolment_memory(user, later), 1);
    }

    /// `enable_2fa` charges the window before it reads anything, so a
    /// throttled caller is refused without touching the database (this stub's
    /// pool can never connect) — and recognisably, by type.
    #[tokio::test]
    async fn a_throttled_enable_is_refused_before_the_database() {
        let service = stub_service(None);
        let user = Uuid::new_v4();
        for _ in 0..MAX_ENROLMENT_ATTEMPTS {
            service.check_enrolment_throttle(user).await.unwrap();
        }
        let err = service
            .enable_2fa(user, "JBSWY3DPEHPK3PXP", "000000", "user@example.com")
            .await
            .expect_err("throttled");
        assert!(
            err.downcast_ref::<EnrolmentThrottled>().is_some(),
            "{err:#}"
        );
    }
}

/// Redis-backed lockout: the property the in-process tests above cannot reach.
///
/// The recorded finding "the 2FA lockout counter is per-process memory" is
/// REFUTED for production — `check_rate_limit` tries Redis first, production
/// fails CLOSED when Redis is unset or unreachable, and the `DashMap` is a
/// development fallback. What was true is that NOTHING drove the Redis path:
/// the cross-instance lockout, the shared counter and its clearing existed
/// only as code. These tests drive the real gate on two SEPARATE `TotpService`
/// instances — separate DashMaps, separate clients — against one Redis.
///
/// Skipped (green) unless `TALOS_TEST_REDIS_URL` is set, and named explicitly
/// by `scripts/test-integration.sh` so it is real coverage there rather than a
/// green skip. Run locally against a disposable Redis:
///
/// ```bash
/// docker run -d --rm -p 16399:6379 redis:7-alpine
/// TALOS_TEST_REDIS_URL=redis://127.0.0.1:16399 \
///   cargo test -p talos-totp-2fa --lib redis_lockout_tests
/// ```
#[cfg(test)]
mod redis_lockout_tests {
    use super::tests::stub_service;
    use super::*;

    /// A fresh service per call: its own `DashMap` and its own client, so a
    /// lockout one instance sees can only have come from Redis.
    fn instance_or_skip() -> Option<TotpService> {
        let url = std::env::var("TALOS_TEST_REDIS_URL").ok()?;
        let client = redis::Client::open(url).expect("valid TALOS_TEST_REDIS_URL");
        Some(stub_service(Some(Arc::new(client))))
    }

    /// The shared counter as Redis holds it.
    async fn read_attempts(service: &TotpService, user_id: Uuid) -> i64 {
        use redis::AsyncCommands as _;
        let mut conn = service
            .redis_client
            .as_ref()
            .expect("redis client")
            .get_multiplexed_async_connection()
            .await
            .expect("redis connection");
        conn.hget::<_, _, Option<i64>>(format!("totp_rate_limit:{user_id}"), "failed_attempts")
            .await
            .expect("read the counter")
            .unwrap_or(0)
    }

    macro_rules! two_instances_or_skip {
        () => {
            match (instance_or_skip(), instance_or_skip()) {
                (Some(a), Some(b)) => (a, b),
                _ => {
                    eprintln!("skipping: TALOS_TEST_REDIS_URL is not set");
                    return;
                }
            }
        };
    }

    /// The attempt past the cap is refused on an instance that never saw one of
    /// the attempts — which is the whole claim the per-process reading denied.
    #[tokio::test]
    async fn a_lockout_on_one_instance_is_enforced_by_the_other() {
        let (a, b) = two_instances_or_skip!();
        let user_id = Uuid::new_v4();

        for attempt in 1..=MAX_2FA_ATTEMPTS {
            a.check_rate_limit(user_id)
                .await
                .unwrap_or_else(|e| panic!("attempt {attempt} on instance A: {e}"));
        }
        let refused = b
            .check_rate_limit(user_id)
            .await
            .expect_err("instance B must refuse the attempt past the shared cap");
        assert!(
            refused.to_string().contains("Too many failed 2FA attempts"),
            "{refused}"
        );
        // And the lockout B wrote is read back by A, which never wrote one.
        let still_locked = a
            .check_rate_limit(user_id)
            .await
            .expect_err("instance A must honour the lockout B recorded");
        assert!(
            still_locked.to_string().contains("Account locked"),
            "{still_locked}"
        );

        // The lockout MARKER, not merely the counter, is what refused that
        // attempt: a locked-out user is turned away BEFORE the pre-charge, so
        // sustained attempts cannot grow the counter without bound. Dropping
        // the `locked_until` HSET leaves every refusal above intact (the
        // pre-charge refuses too, in the same words) and is visible only here.
        let attempts_before = read_attempts(&a, user_id).await;
        a.check_rate_limit(user_id)
            .await
            .expect_err("still locked out");
        assert_eq!(
            read_attempts(&a, user_id).await,
            attempts_before,
            "a refusal under an active lockout must not charge the counter again"
        );

        // Control: another user is unaffected, so the key is per user.
        b.check_rate_limit(Uuid::new_v4())
            .await
            .expect("a different user is not locked out");

        // Neither instance used its in-memory fallback.
        assert!(
            a.rate_limits.is_empty() && b.rate_limits.is_empty(),
            "the Redis path must not touch the per-process counter"
        );
    }

    /// A success on one instance clears the shared counter, so the other
    /// instance grants the full budget again.
    #[tokio::test]
    async fn a_success_on_one_instance_clears_the_counter_for_the_other() {
        let (a, b) = two_instances_or_skip!();
        let user_id = Uuid::new_v4();

        for _ in 0..MAX_2FA_ATTEMPTS - 1 {
            a.check_rate_limit(user_id).await.expect("under the cap");
        }
        b.record_2fa_success(user_id).await;

        for attempt in 1..=MAX_2FA_ATTEMPTS {
            a.check_rate_limit(user_id)
                .await
                .unwrap_or_else(|e| panic!("post-success attempt {attempt}: {e}"));
        }
        a.check_rate_limit(user_id)
            .await
            .expect_err("the cap applies again once the budget is spent");
    }

    /// The production ENTRY POINT is gated by the shared counter before it
    /// touches the database: five attempts through `verify_2fa_login` on one
    /// instance fail at the DB (this pool can never connect), and the sixth on
    /// the OTHER instance is refused by the lockout instead.
    #[tokio::test]
    async fn verify_2fa_login_spends_the_shared_budget_before_any_db_work() {
        let (a, b) = two_instances_or_skip!();
        let user_id = Uuid::new_v4();

        for attempt in 1..=MAX_2FA_ATTEMPTS {
            let err = a
                .verify_2fa_login(user_id, "000000", "user@example.com")
                .await
                .expect_err("the unreachable database fails the attempt");
            assert!(
                !err.to_string().contains("Too many failed 2FA attempts"),
                "attempt {attempt} must reach the DB, not the lockout: {err}"
            );
        }
        let refused = b
            .verify_2fa_login(user_id, "000000", "user@example.com")
            .await
            .expect_err("the attempt past the cap is refused on the other instance");
        assert!(
            refused.to_string().contains("Too many failed 2FA attempts"),
            "the refusal must be the lockout, not a DB error: {refused}"
        );
    }

    /// The enrolment window is shared through Redis: attempts alternate between
    /// two instances and the one past the cap is refused on both. The window
    /// key always carries a TTL no longer than the window.
    #[tokio::test]
    async fn the_enrolment_window_is_shared_across_instances() {
        let (a, b) = two_instances_or_skip!();
        let user_id = Uuid::new_v4();
        for attempt in 1..=MAX_ENROLMENT_ATTEMPTS {
            let who = if attempt % 2 == 0 { &a } else { &b };
            assert_eq!(
                who.check_enrolment_throttle(user_id).await,
                Ok(()),
                "attempt {attempt}"
            );
        }
        assert_eq!(
            a.check_enrolment_throttle(user_id).await,
            Err(EnrolmentThrottled)
        );
        assert_eq!(
            b.check_enrolment_throttle(user_id).await,
            Err(EnrolmentThrottled)
        );
        use redis::AsyncCommands as _;
        let mut conn = a
            .redis_client
            .as_ref()
            .expect("redis client")
            .get_multiplexed_async_connection()
            .await
            .expect("redis connection");
        let ttl: i64 = conn
            .ttl(format!("totp_enrol:{user_id}"))
            .await
            .expect("read the TTL");
        assert!(
            ttl > 0 && ttl <= ENROLMENT_WINDOW_SECS as i64,
            "the window key must expire with the window, TTL {ttl}"
        );
    }
}

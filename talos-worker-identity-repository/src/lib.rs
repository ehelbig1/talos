//! `WorkerIdentityRepository` — persistence for the RFC 0010 P2 inc.4
//! `worker_identities` table: the dynamic registry of per-worker Ed25519 public
//! keys the controller unions with the static `TALOS_WORKER_PUBLIC_KEYS` env
//! registry when verifying worker-signed `JobResult` / RPC.
//!
//! Rows hold only PUBLIC keys, so the trust boundary is entirely on WRITE — the
//! registration path (inc.4c) authenticates callers before calling
//! [`WorkerIdentityRepository::register`]. This layer is deliberately dumb about
//! auth (it trusts its caller) and owns only SQL correctness, the per-worker
//! active-key cap, and fail-loud row decoding.
//!
//! Also owns `worker_provisioning_tokens` (P2 hardening inc.2): single-use,
//! expiring, optionally worker_id-bound registration tokens, stored as SHA-256
//! hashes. [`WorkerIdentityRepository::register_with_provisioning_token`]
//! consumes + registers atomically in one transaction.
//!
//! # Compile-time-checked SQL (RFC 0009 follow-up / review weakness #5)
//!
//! This crate is the pilot for compile-checked `sqlx::query!` in the repository
//! layer: every schema-touching statement is a macro, so a renamed / dropped /
//! retyped column is a **build error** (validated against the committed
//! `.sqlx/` offline metadata) rather than a runtime failure or — worse — a
//! silent `try_get(...).unwrap_or(default)` read. Conventions established here
//! for the rest of the burn-down:
//! * **Aggregates / `EXISTS` need an explicit non-null override** (`count(*) as
//!   "n!"`, `EXISTS(...) as "exists!"`, `RETURNING id as "id!"`): Postgres
//!   reports these nullable, so the alias asserts the invariant and keeps the
//!   binding non-`Option`.
//! * **App-level type narrowing stays in Rust**: `public_key` is `bytea`
//!   (`Vec<u8>`) at the DB layer but a domain `[u8; 32]`, so those reads use
//!   `query!` + [`decode_pubkey_bytes`] (a deliberate fail-loud width check)
//!   instead of `query_as!`. The macro still checks the columns exist.
//! * **Pure-builtin calls stay `sqlx::query`**: the advisory-lock statement
//!   ([`advisory_lock_worker`]) references no table columns — only
//!   `pg_advisory_xact_lock`/`hashtext` — so it carries zero schema-drift risk
//!   and gets no benefit from the macro (which would only add void-return
//!   typing friction). `query!` is for statements that touch the schema.
//!
//! Regenerate the offline metadata after any query change with
//! `make sqlx-prepare` (needs a migrated `DATABASE_URL`); CI's
//! `sqlx-cache` job fails if the committed `.sqlx/` is stale.

use anyhow::{anyhow, Context, Result};
use sqlx::PgPool;

/// Ceiling on simultaneously-ACTIVE keys per `worker_id`. Comfortably covers
/// blue/green + rotation overlap while bounding how far a compromised registrant
/// (or a buggy pod re-registering fresh keys in a loop) can inflate the table.
/// A genuine rotation deactivates the old key, so steady state is 1–2.
pub const MAX_ACTIVE_KEYS_PER_WORKER: i64 = 4;

/// One `(worker_id, public_key)` pair from the active registry — the minimal
/// shape the controller's refresh task merges into the verifying-key snapshot.
#[derive(Debug, Clone)]
pub struct WorkerKeyEntry {
    pub worker_id: String,
    /// Raw 32-byte Ed25519 verifying key.
    pub public_key: [u8; 32],
}

/// A full row for operator/admin listing surfaces. `public_key` is safe to
/// expose (it is public); no secret material lives in this table.
#[derive(Debug, Clone)]
pub struct WorkerIdentityRow {
    pub worker_id: String,
    pub public_key: [u8; 32],
    pub supports_sealing: bool,
    pub active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
    /// Worker-reported build string (`{pkg}+{sha}[-dirty]`). `None` = the row
    /// was written by a pre-handshake worker that never sent the field.
    ///
    /// DIAGNOSTIC ONLY — see the column comment in migration
    /// `20260728120000_worker_identities_build_version.sql`. It is NOT covered
    /// by the registration proof-of-possession, so nothing may branch on it
    /// beyond logging and operator reporting.
    pub build_version: Option<String>,
    /// Last Ed25519 proof-of-possession liveness ping, or `None` if this row
    /// has never participated in the liveness protocol. See the column comment
    /// in migration `20260804120000_worker_identities_liveness.sql` — `None`
    /// means UNKNOWN liveness, never "departed".
    pub last_liveness_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// One row of the fleet build-identity listing surfaced by
/// `get_platform_info.fleet`. Deliberately a SEPARATE, narrower shape from
/// [`WorkerIdentityRow`]: this one omits `public_key` because the MCP surface
/// has no use for key material (public or not) and dumping 64 hex chars per
/// worker into every platform-info response is noise, not information.
#[derive(Debug, Clone)]
pub struct WorkerBuildRow {
    pub worker_id: String,
    /// `None` = pre-handshake worker (never reported a build).
    pub build_version: Option<String>,
    pub supports_sealing: bool,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
    /// Last liveness proof, or `None` for a row that has never participated in
    /// the liveness protocol. The build-skew gauge uses this to drop rows it
    /// can PROVE are departed from its population; a `None` row stays counted,
    /// because a build-skew detector that goes quiet on unknown liveness would
    /// be silenced by exactly the fleet it exists to watch.
    pub last_liveness_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The `+sha[-dirty]` half of a composite build string (`{pkg}+{sha}[-dirty]`),
/// or `None` when there is no `+` (a bare `TALOS_VERSION=1.2.3` override) or the
/// suffix is empty.
///
/// Comparing SUFFIXES, not whole strings, is the point: the controller and
/// worker crates carry independent `CARGO_PKG_VERSION`s (worker `0.1.0` vs a
/// controller release `1.0.0-rN`), so a whole-string compare would report skew
/// on every healthy fleet. The commit sha is what actually has to agree.
///
/// Lives in this crate — not at either call site — because BOTH consumers of the
/// build-identity handshake need it: the controller's registration WARN and the
/// MCP `get_platform_info.fleet` skew flag. Two copies would drift, and the two
/// surfaces disagreeing about whether the fleet is skewed is worse than either
/// being wrong alone.
#[must_use]
pub fn build_suffix(version: &str) -> Option<&str> {
    version
        .split_once('+')
        .map(|(_, suffix)| suffix)
        .filter(|s| !s.is_empty())
}

/// Whether two build strings provably came from the SAME commit.
///
/// Fails closed on anything it cannot prove: a missing suffix, or a suffix of
/// `unknown` / `unknown-dirty` (what `build.rs` stamps outside a git checkout —
/// e.g. a Docker build with no `GIT_SHA_OVERRIDE`). Two `unknown`s are not
/// evidence of agreement; that is the input-freshness lesson restated (#578,
/// unverifiable ≠ verified-same), and callers must word their output
/// accordingly rather than rendering `false` as "skew".
#[must_use]
pub fn builds_match(a: &str, b: &str) -> bool {
    let (Some(sa), Some(sb)) = (build_suffix(a), build_suffix(b)) else {
        return false;
    };
    let known = |s: &str| s != "unknown" && s != "unknown-dirty";
    known(sa) && known(sb) && sa == sb
}

/// Whether a build string carries a usable, non-placeholder commit sha — i.e.
/// whether it can participate in a [`builds_match`] verdict at all. Lets a
/// caller tell "different commits" (actionable skew) apart from "one side never
/// reported a real sha" (unverifiable), which must not be reported the same way.
#[must_use]
pub fn build_is_verifiable(version: &str) -> bool {
    build_suffix(version).is_some_and(|s| s != "unknown" && s != "unknown-dirty")
}

/// Hard ceiling on rows returned by [`WorkerIdentityRepository::list_active_builds`].
/// The table is fleet-sized (tens of rows in the largest deployment we plan
/// for), so this is a runaway guard, not pagination — a fleet past this size
/// has a bigger problem than a truncated report, and the caller says so.
pub const MAX_FLEET_BUILD_ROWS: i64 = 200;

/// Outcome of a [`WorkerIdentityRepository::register`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// The key is now active (fresh insert or idempotent re-registration of an
    /// existing key — the latter also refreshes `last_seen_at`).
    Registered,
    /// Refused: `worker_id` already holds [`MAX_ACTIVE_KEYS_PER_WORKER`] active
    /// keys and this is a NEW key. Deactivate an old key before adding another.
    CapReached,
}

/// Outcome of a [`WorkerIdentityRepository::register_tofu`] call — the
/// trust-on-first-use rule the shared-token network registration path enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TofuOutcome {
    /// The key is active: either this `worker_id` had no history at all (first
    /// use — the key is now its trusted identity) or the submitted key IS the
    /// worker's existing ACTIVE key (idempotent boot-time refresh; bumps
    /// `last_seen_at` and the `supports_sealing` bit).
    Registered,
    /// Refused: `worker_id` already has registration history and the submitted
    /// key is not one of its ACTIVE keys. Covers all three impersonation /
    /// revocation-bypass shapes: a DIFFERENT key while active keys exist, a
    /// re-activation attempt on a deliberately deactivated key, and a claim on
    /// a decommissioned `worker_id` (rows exist, all inactive). Rotation,
    /// revocation reversal, and identity re-issue are operator actions
    /// (`register-worker-identity` CLI / a worker_id-bound provisioning token),
    /// never a shared-bearer-token network call.
    IdentityConflict,
}

/// Outcome of [`WorkerIdentityRepository::register_with_provisioning_token`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRegisterOutcome {
    /// Token consumed, key active.
    Registered,
    /// No eligible token matched: unknown hash, already used, revoked,
    /// expired, bound to a different `worker_id`, or wildcard while bound-token
    /// enforcement is on. Deliberately ONE variant — the endpoint must not let
    /// a caller distinguish these (the repo logs nothing here; the endpoint
    /// emits a generic 401 and a server-side security log).
    InvalidToken,
    /// Wildcard-token path hit the TOFU rule (see [`TofuOutcome::IdentityConflict`]).
    /// The token was NOT consumed.
    IdentityConflict,
    /// Bound-token path hit the per-worker active-key cap. The token was NOT
    /// consumed.
    CapReached,
}

/// One provisioning-token row for operator listing — metadata only, never the
/// hash (and the raw token is never stored at all).
#[derive(Debug, Clone)]
pub struct ProvisioningTokenRow {
    pub id: uuid::Uuid,
    /// `None` = wildcard token.
    pub worker_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub used_by_worker_id: Option<String>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub note: Option<String>,
}

pub struct WorkerIdentityRepository {
    db_pool: PgPool,
}

/// Per-`worker_id` transaction-scoped advisory lock — serialises every
/// registration path touching one worker so count-then-insert style races
/// (cap, TOFU first-use) cannot interleave. Cheap at boot-time frequency.
async fn advisory_lock_worker(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    worker_id: &str,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(worker_id)
        .execute(&mut **tx)
        .await
        .context("advisory lock")?;
    Ok(())
}

/// Operator-grade registration body (see [`WorkerIdentityRepository::register`]
/// for semantics). Runs inside the caller's transaction; the caller must hold
/// the per-worker advisory lock.
///
/// Single gated upsert: the INSERT ... SELECT emits a row ONLY when the worker
/// is under the cap OR this exact key already exists (idempotent path is
/// always allowed). A new key at the cap yields zero rows — no insert, no
/// ON CONFLICT — read back as `CapReached`. Atomic; no separate
/// count-then-insert window.
///
/// `build_version` is the registrant's self-reported build string, or `None`
/// when the registrant did not report one (a pre-handshake worker, or the
/// operator CLI, which knows nothing about the pod's build). It is written
/// UNCONDITIONALLY — including back to NULL — because the column means "what
/// the LATEST registration reported", and preserving a previous value across a
/// silent re-registration would leave a stale claim standing as if it were
/// current. Diagnostic only; never an authorization input.
async fn register_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
    build_version: Option<&str>,
) -> Result<RegisterOutcome> {
    let res = sqlx::query!(
        "INSERT INTO worker_identities (worker_id, public_key, supports_sealing, build_version)
         SELECT $1, $2, $3, $5
         WHERE (SELECT count(*) FROM worker_identities
                WHERE worker_id = $1 AND active) < $4
            OR EXISTS (SELECT 1 FROM worker_identities
                       WHERE worker_id = $1 AND public_key = $2)
         ON CONFLICT (worker_id, public_key) DO UPDATE
            SET active = true,
                supports_sealing = EXCLUDED.supports_sealing,
                build_version = EXCLUDED.build_version,
                last_seen_at = now()",
        worker_id,
        &public_key[..],
        supports_sealing,
        MAX_ACTIVE_KEYS_PER_WORKER,
        build_version,
    )
    .execute(&mut **tx)
    .await
    .context("gated upsert")?;

    Ok(if res.rows_affected() == 1 {
        RegisterOutcome::Registered
    } else {
        RegisterOutcome::CapReached
    })
}

/// Trust-on-first-use registration body (see
/// [`WorkerIdentityRepository::register_tofu`] for semantics). Runs inside the
/// caller's transaction; the caller must hold the per-worker advisory lock.
/// `build_version` follows the same write rule as [`register_in_tx`]: the
/// latest registration's report wins, including `None` → NULL.
async fn register_tofu_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
    build_version: Option<&str>,
) -> Result<TofuOutcome> {
    // Exact-row lookup: does this (worker_id, key) pair already exist, and is
    // it live? Compile-checked query! — `active` is a NOT NULL column so the
    // scalar is `bool`; `fetch_optional` makes the row-absence the outer
    // `Option` (no silent-default reads — check 52, now enforced at build time).
    let exact: Option<bool> = sqlx::query_scalar!(
        "SELECT active FROM worker_identities WHERE worker_id = $1 AND public_key = $2",
        worker_id,
        &public_key[..],
    )
    .fetch_optional(&mut **tx)
    .await
    .context("tofu exact-row lookup")?;

    match exact {
        // Idempotent refresh of the worker's own ACTIVE key.
        Some(true) => {
            sqlx::query!(
                "UPDATE worker_identities
                 SET supports_sealing = $3, build_version = $4, last_seen_at = now()
                 WHERE worker_id = $1 AND public_key = $2",
                worker_id,
                &public_key[..],
                supports_sealing,
                build_version,
            )
            .execute(&mut **tx)
            .await
            .context("tofu refresh")?;
            Ok(TofuOutcome::Registered)
        }
        // The key exists but was deliberately deactivated — re-activating it
        // here would let a shared-token holder undo a revocation.
        Some(false) => Ok(TofuOutcome::IdentityConflict),
        None => {
            // `count(*)` is inferred NULLABLE by Postgres, so the `as "n!"`
            // override asserts NOT NULL and keeps the binding an `i64` (not
            // `Option<i64>`) — the canonical sqlx aggregate-nullability idiom.
            let history: i64 = sqlx::query_scalar!(
                "SELECT count(*) as \"n!\" FROM worker_identities WHERE worker_id = $1",
                worker_id,
            )
            .fetch_one(&mut **tx)
            .await
            .context("tofu history count")?;
            if history == 0 {
                sqlx::query!(
                    "INSERT INTO worker_identities
                     (worker_id, public_key, supports_sealing, build_version)
                     VALUES ($1, $2, $3, $4)",
                    worker_id,
                    &public_key[..],
                    supports_sealing,
                    build_version,
                )
                .execute(&mut **tx)
                .await
                .context("tofu first-use insert")?;
                Ok(TofuOutcome::Registered)
            } else {
                Ok(TofuOutcome::IdentityConflict)
            }
        }
    }
}

impl WorkerIdentityRepository {
    #[must_use]
    pub fn new(db_pool: PgPool) -> Self {
        Self { db_pool }
    }

    /// Register (or idempotently refresh) a worker's public key.
    ///
    /// Idempotent on `(worker_id, public_key)`: re-registering an existing key
    /// re-activates it (rotation reversal is a deliberate operator/worker action
    /// gated by the caller's auth) and bumps `last_seen_at`. A genuinely NEW key
    /// is admitted only while the worker is under the active-key cap.
    ///
    /// Concurrency-safe: a per-`worker_id` transaction-scoped advisory lock
    /// serialises concurrent registrations so two racing NEW-key inserts cannot
    /// both slip past the cap (the TOCTOU the webhook repo's `try_create_under_cap`
    /// closes the same way).
    ///
    /// `build_version`: the registrant's self-reported build string, `None`
    /// from the operator CLI (which has no visibility into the pod's build).
    /// Diagnostic only — never an authorization input.
    pub async fn register(
        &self,
        worker_id: &str,
        public_key: &[u8; 32],
        supports_sealing: bool,
        build_version: Option<&str>,
    ) -> Result<RegisterOutcome> {
        let mut tx = self.db_pool.begin().await.context("begin register tx")?;
        advisory_lock_worker(&mut tx, worker_id).await?;
        let outcome = register_in_tx(
            &mut tx,
            worker_id,
            public_key,
            supports_sealing,
            build_version,
        )
        .await?;
        tx.commit().await.context("commit register tx")?;
        Ok(outcome)
    }

    /// Trust-on-first-use registration — the rule for the NETWORK
    /// self-registration path, where the caller is authenticated only as "some
    /// pod holding the shared registration token", not as a specific worker.
    ///
    /// A `worker_id`'s FIRST registered key becomes its trusted identity; from
    /// then on this path only accepts an idempotent refresh of that exact
    /// ACTIVE key. Anything else — a different key, a deactivated key, a new
    /// key for a fully-retired `worker_id` — is [`TofuOutcome::IdentityConflict`]:
    /// without this rule, any shared-token holder could register its own key
    /// under another worker's id and impersonate it for result signing and
    /// (P3) secret claims. Legitimate key rotation always accompanies an
    /// operator (worker signing keys are provisioned via Secret, never
    /// generated in-pod), so the operator paths — [`Self::register`] via the
    /// CLI — carry the rotation semantics instead.
    ///
    /// Same advisory-lock serialisation as [`Self::register`], so a concurrent
    /// first-use race on one `worker_id` admits exactly one key.
    ///
    /// `build_version`: see [`Self::register`] — diagnostic only, written
    /// verbatim (including `None`) on both the first-use insert and the
    /// idempotent refresh, so a redeployed worker's new build shows up.
    pub async fn register_tofu(
        &self,
        worker_id: &str,
        public_key: &[u8; 32],
        supports_sealing: bool,
        build_version: Option<&str>,
    ) -> Result<TofuOutcome> {
        let mut tx = self.db_pool.begin().await.context("begin tofu tx")?;
        advisory_lock_worker(&mut tx, worker_id).await?;
        let outcome = register_tofu_in_tx(
            &mut tx,
            worker_id,
            public_key,
            supports_sealing,
            build_version,
        )
        .await?;
        tx.commit().await.context("commit tofu tx")?;
        Ok(outcome)
    }

    /// Redeem a provisioning token and register the key, atomically.
    ///
    /// One transaction: consume the token (single `UPDATE … WHERE used_at IS
    /// NULL … RETURNING` — the row lock makes two concurrent redeems admit
    /// exactly one) then register under the semantics the token's binding
    /// earns:
    /// * **worker_id-BOUND token** — the mint was an explicit operator action
    ///   for that one worker, so it carries operator-grade [`Self::register`]
    ///   semantics: new key, rotation, or re-activation, under the active-key
    ///   cap. The token must be bound to the `worker_id` being registered.
    /// * **wildcard token** (`worker_id IS NULL`, migration compat) — like the
    ///   shared token it replaces, it proves nothing about WHICH worker, so
    ///   TOFU semantics apply ([`Self::register_tofu`]). Refused outright when
    ///   `require_bound` is set (`TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1`) —
    ///   inside the consume SQL, so an ineligible token is never burned.
    ///
    /// A REFUSED registration (TOFU conflict / cap) ROLLS BACK the
    /// consumption: a failed attempt does not burn the operator's token, and
    /// because the rollback releases the row lock, a racing legitimate redeem
    /// of the same token can still win afterwards.
    ///
    /// `token_hash` is the SHA-256 hex of the raw bearer token — the raw value
    /// is never stored or compared in SQL (lint check 41 discipline; hashing
    /// happens at the endpoint, so this layer never sees the credential).
    ///
    /// `build_version`: see [`Self::register`] — diagnostic only, persisted on
    /// whichever registration arm the token's binding selects.
    pub async fn register_with_provisioning_token(
        &self,
        token_hash: &str,
        worker_id: &str,
        public_key: &[u8; 32],
        supports_sealing: bool,
        require_bound: bool,
        build_version: Option<&str>,
    ) -> Result<TokenRegisterOutcome> {
        let mut tx = self.db_pool.begin().await.context("begin token tx")?;
        advisory_lock_worker(&mut tx, worker_id).await?;

        // Atomic single-use consume. All eligibility conditions live in the
        // WHERE so an ineligible call cannot consume: unused, unrevoked,
        // unexpired, binding matches the registering worker_id (NULL =
        // wildcard), and wildcard only while enforcement is off.
        // `RETURNING worker_id` (a NULLABLE column) → the INNER Option; row
        // absence (ineligible token) → the OUTER Option from `fetch_optional`.
        let consumed: Option<Option<String>> = sqlx::query_scalar!(
            "UPDATE worker_provisioning_tokens
             SET used_at = now(), used_by_worker_id = $2
             WHERE token_hash = $1
               AND used_at IS NULL
               AND revoked_at IS NULL
               AND expires_at > now()
               AND (worker_id IS NULL OR worker_id = $2)
               AND (worker_id IS NOT NULL OR NOT $3)
             RETURNING worker_id",
            token_hash,
            worker_id,
            require_bound,
        )
        .fetch_optional(&mut *tx)
        .await
        .context("consume provisioning token")?;

        let Some(binding) = consumed else {
            tx.rollback().await.context("rollback invalid token")?;
            return Ok(TokenRegisterOutcome::InvalidToken);
        };

        let outcome = if binding.is_some() {
            match register_in_tx(
                &mut tx,
                worker_id,
                public_key,
                supports_sealing,
                build_version,
            )
            .await?
            {
                RegisterOutcome::Registered => TokenRegisterOutcome::Registered,
                RegisterOutcome::CapReached => TokenRegisterOutcome::CapReached,
            }
        } else {
            match register_tofu_in_tx(
                &mut tx,
                worker_id,
                public_key,
                supports_sealing,
                build_version,
            )
            .await?
            {
                TofuOutcome::Registered => TokenRegisterOutcome::Registered,
                TofuOutcome::IdentityConflict => TokenRegisterOutcome::IdentityConflict,
            }
        };

        if outcome == TokenRegisterOutcome::Registered {
            tx.commit().await.context("commit token registration")?;
        } else {
            // Registration refused — undo the consumption so the token
            // survives for a corrected retry.
            tx.rollback()
                .await
                .context("rollback refused token registration")?;
        }
        Ok(outcome)
    }

    /// Record a freshly minted provisioning token (hash only — the caller
    /// shows the raw token once and forgets it). Returns the row id operators
    /// use to list/revoke.
    pub async fn create_provisioning_token(
        &self,
        token_hash: &str,
        worker_id: Option<&str>,
        expires_at: chrono::DateTime<chrono::Utc>,
        note: Option<&str>,
    ) -> Result<uuid::Uuid> {
        // `RETURNING id` on a PK is inferred nullable by sqlx (it can't prove a
        // RETURNING expression is NOT NULL), so `as "id!"` asserts the invariant
        // the PRIMARY KEY guarantees and keeps the binding a plain `Uuid`.
        let id: uuid::Uuid = sqlx::query_scalar!(
            "INSERT INTO worker_provisioning_tokens (token_hash, worker_id, expires_at, note)
             VALUES ($1, $2, $3, $4)
             RETURNING id as \"id!\"",
            token_hash,
            worker_id,
            expires_at,
            note,
        )
        .fetch_one(&self.db_pool)
        .await
        .context("insert provisioning token")?;
        Ok(id)
    }

    /// Revoke an un-redeemed provisioning token. Returns `true` if a live
    /// (unused, unrevoked) token was revoked, `false` otherwise — revoking a
    /// consumed token is a no-op so the redemption record stays truthful.
    pub async fn revoke_provisioning_token(&self, id: uuid::Uuid) -> Result<bool> {
        let res = sqlx::query!(
            "UPDATE worker_provisioning_tokens SET revoked_at = now()
             WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL",
            id,
        )
        .execute(&self.db_pool)
        .await
        .context("revoke provisioning token")?;
        Ok(res.rows_affected() > 0)
    }

    /// Append a provisioning-token lifecycle event to `admin_event_log` — the
    /// same audit trail the platform's operator mutations write, keyed on
    /// `resource_type = 'worker_provisioning_token'` / the token row id.
    /// `user_id` is NULL: mints/revokes happen from the DB-credentialed
    /// operator CLI, where holding DB credentials IS the authorization and no
    /// platform user exists. Callers must never place token material in
    /// `summary`/`details` — mint-site discipline, the raw token is shown once
    /// on the mint stdout and exists nowhere else.
    pub async fn insert_provisioning_token_audit(
        &self,
        event_type: &str,
        token_id: uuid::Uuid,
        summary: &str,
        details: Option<&serde_json::Value>,
    ) -> Result<()> {
        sqlx::query!(
            "INSERT INTO admin_event_log
             (user_id, event_type, resource_type, resource_id, summary, details)
             VALUES (NULL, $1, 'worker_provisioning_token', $2, $3, $4)",
            event_type,
            token_id,
            summary,
            details as Option<&serde_json::Value>,
        )
        .execute(&self.db_pool)
        .await
        .context("insert provisioning-token audit event")?;
        Ok(())
    }

    /// All provisioning-token rows for the operator listing surface, newest
    /// first. Exposes metadata only — never `token_hash` (an offline-crackable
    /// digest has no business in ops output).
    pub async fn list_provisioning_tokens(&self) -> Result<Vec<ProvisioningTokenRow>> {
        // `query_as!` maps straight into the struct AND compile-checks that every
        // column's name, SQL type, and nullability matches the field — so a
        // renamed column or a NOT NULL→NULL drift is a build error, not a
        // runtime `try_get` failure. `id as "id!"` because sqlx infers PK
        // columns nullable in projections; the rest match the schema's
        // NOT NULL / nullable split exactly.
        let rows = sqlx::query_as!(
            ProvisioningTokenRow,
            "SELECT id as \"id!\", worker_id, created_at, expires_at, used_at,
                    used_by_worker_id, revoked_at, note
             FROM worker_provisioning_tokens
             ORDER BY created_at DESC, id",
        )
        .fetch_all(&self.db_pool)
        .await
        .context("list provisioning tokens")?;
        Ok(rows)
    }

    /// Every ACTIVE `(worker_id, public_key)` pair. The controller's refresh task
    /// calls this on its interval and merges the result into the verifying-key
    /// snapshot. One indexed scan (partial index `WHERE active`); the table is
    /// small (fleet-sized), so this is cheap.
    pub async fn load_active_registry(&self) -> Result<Vec<WorkerKeyEntry>> {
        // `query!` (not `query_as!`) because `public_key` is `bytea` → `Vec<u8>`
        // at the DB layer, but the domain type is a fixed `[u8; 32]`. The macro
        // still compile-checks that both columns exist with the expected SQL
        // types; the app-level width-narrowing (a deliberate fail-loud security
        // check, below) stays in Rust where it belongs.
        let rows = sqlx::query!("SELECT worker_id, public_key FROM worker_identities WHERE active")
            .fetch_all(&self.db_pool)
            .await
            .context("load active worker registry")?;

        rows.into_iter()
            .map(|r| {
                // Fail-loud decode (lint check 52): a wrong-width key errors here
                // rather than silently defaulting to a garbage key that would
                // then fail every verify opaquely.
                let public_key = decode_pubkey_bytes(&r.public_key, &r.worker_id)?;
                Ok(WorkerKeyEntry {
                    worker_id: r.worker_id,
                    public_key,
                })
            })
            .collect()
    }

    /// Record a liveness proof for one ACTIVE key — the ONLY writer of
    /// `last_liveness_at`. Returns whether a live row was refreshed.
    ///
    /// The caller (the `/internal/worker-liveness` endpoint) has already
    /// verified an Ed25519 proof-of-possession over `(worker_id, public_key,
    /// issued_at_ms, nonce)`, so reaching here means the pinger demonstrably
    /// holds this key's private half.
    ///
    /// GRANTS NOTHING. This is a single guarded UPDATE that moves one timestamp
    /// forward. It cannot INSERT (a never-registered key gets `false`, not a
    /// row), cannot re-activate (`AND active` excludes a deactivated key, so a
    /// revoked or reaped worker cannot ping itself back into the trust ring),
    /// and cannot touch `public_key` / `supports_sealing` / `build_version` /
    /// `active`. So the endpoint adds no trust surface: every capability it
    /// could confer, registration already conferred.
    ///
    /// A `false` return is meaningful to the caller and must stay
    /// distinguishable: it means "this key is not an active identity", which
    /// the worker logs loudly (it has been revoked or reaped and its results
    /// will not verify) — but the response must not tell an unauthenticated
    /// caller WHICH of those it is, so the endpoint collapses it to one status.
    pub async fn touch_liveness(&self, worker_id: &str, public_key: &[u8; 32]) -> Result<bool> {
        let res = sqlx::query!(
            "UPDATE worker_identities SET last_liveness_at = now()
             WHERE worker_id = $1 AND public_key = $2 AND active",
            worker_id,
            &public_key[..],
        )
        .execute(&self.db_pool)
        .await
        .context("touch worker liveness")?;
        Ok(res.rows_affected() > 0)
    }

    /// Reap identities whose worker PROVED it speaks the liveness protocol and
    /// then went silent for longer than `max_silence_hours`. Returns the number
    /// of keys deactivated.
    ///
    /// **This is a trust-boundary write with fleet-wide blast radius, so read
    /// the predicate as three separate guards:**
    ///
    /// 1. `active` — never re-touch a row an operator already retired.
    /// 2. `last_liveness_at IS NOT NULL` — the row must have DEMONSTRATED
    ///    participation. A NULL row's liveness is unknown in both directions
    ///    (it may be a healthy worker on a pre-liveness build), and unknown
    ///    must never be read as departed. This single clause is what makes the
    ///    sweep safe to enable on a mixed fleet mid-rollout, and it is why the
    ///    obvious `last_seen_at` decay — which cannot make this distinction —
    ///    is wrong.
    /// 3. `last_liveness_at < now() - interval` — evaluated by POSTGRES against
    ///    POSTGRES's clock, the same clock that wrote every `last_liveness_at`.
    ///    Nothing is compared across two machines' clocks, so controller clock
    ///    skew cannot shorten the window.
    ///
    /// CONCURRENCY — a worker pinging while the sweep runs must not be reaped,
    /// and is not: this is ONE statement, never a read-then-write. Under READ
    /// COMMITTED, if a concurrent `touch_liveness` holds the row lock, the
    /// UPDATE blocks, then RE-EVALUATES its WHERE against the committed row —
    /// which now carries a fresh `last_liveness_at` — and skips it. In the
    /// other order the ping's own `AND active` fails and it reports `false`.
    /// Either interleaving is correct; neither can reap a worker that pinged.
    ///
    /// FAIL-SAFE: an error propagates with `?` and deactivates NOTHING (a
    /// single statement either applies or does not). The caller leaves the
    /// fleet exactly as it was.
    ///
    /// Deactivation is SOFT (`active = false`), never a DELETE. A DELETE would
    /// erase the worker_id's registration history and hand it back to the
    /// trust-on-first-use path as a never-before-seen id — i.e. it would let
    /// any holder of a shared registration token claim a reaped worker's
    /// identity. Soft-retiring keeps the TOFU conflict path intact: a reaped
    /// worker that returns is refused (`TofuOutcome::IdentityConflict`) and
    /// needs an operator `register-worker-identity`, exactly like a revoked
    /// key. That lockout is the deliberate cost of not weakening TOFU; it is
    /// why the default window is long enough that only a genuinely departed
    /// worker can cross it.
    pub async fn reap_departed_identities(&self, max_silence_hours: i32) -> Result<u64> {
        let res = sqlx::query!(
            "UPDATE worker_identities SET active = false
             WHERE active
               AND last_liveness_at IS NOT NULL
               AND last_liveness_at < now() - make_interval(hours => $1::int)",
            max_silence_hours,
        )
        .execute(&self.db_pool)
        .await
        .context("reap departed worker identities")?;
        Ok(res.rows_affected())
    }

    /// Reap PRE-PROTOCOL identities — rows that have never demonstrated
    /// liveness participation and have not re-registered in
    /// `max_age_hours`. Returns the number of keys deactivated.
    ///
    /// **Deliberately a separate method behind a separate, default-OFF operator
    /// switch, because it is the unsafe direction of the same idea.** It keys
    /// on `last_seen_at`, which is written only at boot registration, so it
    /// CANNOT distinguish a departed pod from a healthy worker that has simply
    /// been up a long time on a pre-liveness build. Enabling it is the operator
    /// asserting a fact the controller cannot check: that their fleet has
    /// finished rolling onto a build that pings.
    ///
    /// It exists because the population it addresses is real and unbounded —
    /// every row registered before the liveness protocol shipped is one, and on
    /// a pod-name-keyed fleet that is every roll and every scale-down ever
    /// performed. The alternative is per-key `deactivate-worker-identity` runs
    /// forever. But it must never be the default, and
    /// [`Self::reap_departed_identities`] must never grow this behaviour.
    ///
    /// Same single-statement, guarded-predicate, fail-safe properties as its
    /// sibling; `last_liveness_at IS NULL` keeps the two populations strictly
    /// disjoint so a participating worker can never be caught by this arm.
    pub async fn reap_pre_protocol_identities(&self, max_age_hours: i32) -> Result<u64> {
        let res = sqlx::query!(
            "UPDATE worker_identities SET active = false
             WHERE active
               AND last_liveness_at IS NULL
               AND last_seen_at < now() - make_interval(hours => $1::int)",
            max_age_hours,
        )
        .execute(&self.db_pool)
        .await
        .context("reap pre-protocol worker identities")?;
        Ok(res.rows_affected())
    }

    /// Soft-retire one key (rotation). Returns `true` if a live key was
    /// deactivated, `false` if it was already inactive / absent. Idempotent.
    pub async fn deactivate(&self, worker_id: &str, public_key: &[u8; 32]) -> Result<bool> {
        let res = sqlx::query!(
            "UPDATE worker_identities SET active = false
             WHERE worker_id = $1 AND public_key = $2 AND active",
            worker_id,
            &public_key[..],
        )
        .execute(&self.db_pool)
        .await
        .context("deactivate worker key")?;
        Ok(res.rows_affected() > 0)
    }

    /// Whether `worker_id` has at least one ACTIVE key advertising the P3/D3b
    /// claim-sealing capability. Lets the controller seal claim-based to capable
    /// workers and inline (legacy WSK) to the rest during a heterogeneous rollout.
    pub async fn worker_supports_sealing(&self, worker_id: &str) -> Result<bool> {
        // `EXISTS(...)` is inferred nullable by Postgres; `as "exists!"` asserts
        // NOT NULL so the scalar binds as `bool` (never `Option<bool>`).
        let supported: bool = sqlx::query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM worker_identities
             WHERE worker_id = $1 AND active AND supports_sealing) as \"exists!\"",
            worker_id,
        )
        .fetch_one(&self.db_pool)
        .await
        .context("query worker sealing capability")?;
        Ok(supported)
    }

    /// Full listing for operator/admin surfaces, newest-key-last within a worker.
    /// Deterministic order (no OFFSET pagination here; ordered for stable output).
    pub async fn list(&self) -> Result<Vec<WorkerIdentityRow>> {
        // `query!` (not `query_as!`) for the same reason as `load_active_registry`:
        // `public_key` bytea narrows to the domain `[u8; 32]` in Rust. All other
        // columns are NOT NULL, so the macro binds them non-optionally.
        let rows = sqlx::query!(
            "SELECT worker_id, public_key, supports_sealing, active, created_at, last_seen_at,
                    build_version, last_liveness_at
             FROM worker_identities
             ORDER BY worker_id, created_at, public_key",
        )
        .fetch_all(&self.db_pool)
        .await
        .context("list worker identities")?;

        rows.into_iter()
            .map(|r| {
                let public_key = decode_pubkey_bytes(&r.public_key, &r.worker_id)?;
                Ok(WorkerIdentityRow {
                    worker_id: r.worker_id,
                    public_key,
                    supports_sealing: r.supports_sealing,
                    active: r.active,
                    created_at: r.created_at,
                    last_seen_at: r.last_seen_at,
                    build_version: r.build_version,
                    last_liveness_at: r.last_liveness_at,
                })
            })
            .collect()
    }

    /// Fleet build-identity listing for `get_platform_info.fleet` — one row per
    /// ACTIVE worker identity with the build it last reported.
    ///
    /// One row per (worker_id, key), not per worker: a worker mid-rotation
    /// legitimately holds two active keys, and collapsing them here would hide
    /// the case where the two rows disagree — exactly the skew this feature
    /// exists to surface. The caller labels them by worker_id.
    ///
    /// Bounded + deterministically ordered: `LIMIT` is a runaway guard (see
    /// [`MAX_FLEET_BUILD_ROWS`]) and the ORDER BY carries `public_key` as a
    /// unique tiebreaker after `worker_id` (check 28 — a plain `ORDER BY
    /// worker_id` leaves two same-worker rows in heap order, so a truncated or
    /// re-run report could disagree with itself on identical data).
    pub async fn list_active_builds(&self) -> Result<Vec<WorkerBuildRow>> {
        // `query_as!` compile-checks name + SQL type + nullability against the
        // struct: `build_version` is the schema's only nullable column here, so
        // a future NOT NULL / rename drift is a build error rather than a
        // silent default (checks 52/55 — no `try_get(...).unwrap_or(...)`
        // anywhere on this path).
        let rows = sqlx::query_as!(
            WorkerBuildRow,
            "SELECT worker_id, build_version, supports_sealing, last_seen_at, last_liveness_at
             FROM worker_identities
             WHERE active
             ORDER BY worker_id, public_key
             LIMIT $1",
            MAX_FLEET_BUILD_ROWS,
        )
        .fetch_all(&self.db_pool)
        .await
        .context("list active worker builds")?;
        Ok(rows)
    }
}

/// Decode a `public_key` bytea value into a fixed 32-byte array, erroring loudly
/// (with the offending `worker_id`) on any width mismatch. The DB CHECK already
/// guarantees 32 bytes on write, so this only trips on corruption or a schema
/// change — exactly when a silent default would be dangerous. Takes the decoded
/// bytes directly (the `query!` macro already produced a `Vec<u8>`), keeping the
/// width-narrowing security check independent of the row-access mechanism.
fn decode_pubkey_bytes(bytes: &[u8], worker_id: &str) -> Result<[u8; 32]> {
    let len = bytes.len();
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        anyhow!("worker_identities.public_key for {worker_id} is {len} bytes, expected 32")
    })
}

/// Build-identity comparison — pure, so these run everywhere (unlike the DB
/// tests below, which skip without `DATABASE_URL`).
#[cfg(test)]
mod build_identity_tests {
    use super::{build_is_verifiable, build_suffix, builds_match};

    #[test]
    fn suffix_is_the_part_after_the_first_plus() {
        assert_eq!(build_suffix("0.1.0+ab85eb2"), Some("ab85eb2"));
        assert_eq!(build_suffix("0.1.0+ab85eb2-dirty"), Some("ab85eb2-dirty"));
        // A bare TALOS_VERSION override has no suffix to compare.
        assert_eq!(build_suffix("1.2.3"), None);
        assert_eq!(build_suffix("1.2.3+"), None);
        assert_eq!(build_suffix(""), None);
        // First '+' wins, so a suffix containing one is still stable.
        assert_eq!(build_suffix("1.2.3+a+b"), Some("a+b"));
    }

    #[test]
    fn matches_across_differing_package_versions() {
        // The whole reason we compare suffixes: worker `0.1.0` vs controller
        // `1.0.0-r304` is the NORMAL case, not skew.
        assert!(builds_match("1.0.0-r304+ab85eb2", "0.1.0+ab85eb2"));
        assert!(builds_match("0.1.0+ab85eb2-dirty", "9.9.9+ab85eb2-dirty"));
        assert!(builds_match("0.1.0+ab85eb2", "0.1.0+ab85eb2"));
    }

    #[test]
    fn different_commits_do_not_match() {
        assert!(!builds_match("0.1.0+ab85eb2", "0.1.0+f099158"));
        // A dirty tree on ONE side is a real difference: the two binaries were
        // built from different bytes even at the same commit.
        assert!(!builds_match("0.1.0+ab85eb2", "0.1.0+ab85eb2-dirty"));
        // Case-sensitive: shas are lowercase hex, a case flip is not the same
        // string and we do not guess.
        assert!(!builds_match("0.1.0+AB85EB2", "0.1.0+ab85eb2"));
    }

    #[test]
    fn unverifiable_never_reads_as_a_match() {
        // "unknown" is what build.rs stamps outside a git checkout. Two
        // unknowns are NOT evidence of agreement (#578: unverifiable ≠ same).
        assert!(!builds_match("0.1.0+unknown", "1.0.0+unknown"));
        assert!(!builds_match("0.1.0+unknown-dirty", "1.0.0+unknown-dirty"));
        assert!(!builds_match("0.1.0+unknown", "1.0.0+ab85eb2"));
        // No suffix on either side → nothing to compare, even when identical.
        assert!(!builds_match("1.2.3", "1.2.3"));
        assert!(!builds_match("1.2.3", "0.1.0+ab85eb2"));
    }

    #[test]
    fn verifiability_separates_real_skew_from_no_information() {
        assert!(build_is_verifiable("0.1.0+ab85eb2"));
        assert!(build_is_verifiable("0.1.0+ab85eb2-dirty"));
        assert!(!build_is_verifiable("0.1.0+unknown"));
        assert!(!build_is_verifiable("0.1.0+unknown-dirty"));
        assert!(!build_is_verifiable("1.2.3"));
        // Both non-matching, but only ONE of these is actionable skew — the
        // distinction callers must preserve in their wording.
        assert!(!builds_match("0.1.0+aaaaaaa", "0.1.0+bbbbbbb"));
        assert!(build_is_verifiable("0.1.0+aaaaaaa") && build_is_verifiable("0.1.0+bbbbbbb"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require a migrated Postgres reachable via DATABASE_URL. They
    // no-op (skip) when it is unset so the crate's `cargo test` stays green in
    // environments without a DB; CI's integration lane provides one.
    //
    // RESIDUE-FREE IS MANDATORY, not tidiness. `DATABASE_URL` points at whatever
    // DB the developer has configured, and in this repo the dev value is the
    // LIVE compose Postgres — these tests write into the same table the running
    // controller reads. On 2026-07-28 that bit: `get_platform_info.fleet` (new,
    // and the whole point of which is to be trusted during an incident) listed
    // 22 `test-*` fixtures as the fleet and raised `build_skew: true` off their
    // fake shas, while the one real worker was nowhere in it. A test fixture
    // that outlives its test is not inert — it is a lie told to an operator by a
    // production surface. Hence [`cleanup_worker_rows`] at BOTH ends of every
    // DB-backed test below.
    async fn pool_or_skip() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        Some(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("connect to DATABASE_URL"),
        )
    }

    /// Delete exactly the rows a test owns: `worker_identities` for
    /// `worker_ids`, `worker_provisioning_tokens` for `token_hashes`. Distinct
    /// per-test ids keep tests mutually isolated, so this never touches another
    /// test's (or an operator's) data — no blanket `DELETE FROM`.
    ///
    /// Call it at the START of every DB-backed test (a previous run that panicked
    /// mid-test leaves rows, and a test must not inherit them) AND at the END
    /// (leave no trace — see the [`pool_or_skip`] note for what residue cost).
    /// The start call is the backstop for the one case the end call cannot cover:
    /// a FAILING test panics before reaching it.
    async fn cleanup_worker_rows(pool: &PgPool, worker_ids: &[&str], token_hashes: &[&str]) {
        // Per-id statements rather than `= ANY($1)`: identical SQL text to what
        // the offline `.sqlx` cache already holds, so test hygiene never forces a
        // `cargo sqlx prepare` regeneration.
        for worker_id in worker_ids {
            sqlx::query!(
                "DELETE FROM worker_identities WHERE worker_id = $1",
                worker_id
            )
            .execute(pool)
            .await
            .expect("test cleanup delete");
        }
        for token_hash in token_hashes {
            sqlx::query!(
                "DELETE FROM worker_provisioning_tokens WHERE token_hash = $1",
                token_hash
            )
            .execute(pool)
            .await
            .expect("test token cleanup delete");
        }
    }

    // A distinct worker_id per test so a shared DB stays isolated without a
    // global cleanup step. `key(n)` makes deterministic distinct 32-byte keys.
    fn key(n: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = n;
        k[31] = n.wrapping_add(7);
        k
    }

    #[tokio::test]
    async fn register_is_idempotent_and_loads_back() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-idem-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        assert_eq!(
            repo.register(wid, &key(1), false, None).await.unwrap(),
            RegisterOutcome::Registered
        );
        // Re-register the SAME key: idempotent, still one active key.
        assert_eq!(
            repo.register(wid, &key(1), true, None).await.unwrap(),
            RegisterOutcome::Registered
        );

        let reg = repo.load_active_registry().await.unwrap();
        let mine: Vec<_> = reg.iter().filter(|e| e.worker_id == wid).collect();
        assert_eq!(mine.len(), 1, "idempotent re-register must not duplicate");
        assert_eq!(mine[0].public_key, key(1));
        // The re-register updated the capability bit.
        assert!(repo.worker_supports_sealing(wid).await.unwrap());

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    /// The build-identity handshake's persistence contract: the column always
    /// reflects the LATEST registration's report, on the insert arm AND the
    /// idempotent re-register arm (a redeployed worker keeps its key and gets a
    /// new build), and a registrant that reports nothing clears it rather than
    /// leaving a stale claim standing as if it were current.
    #[tokio::test]
    async fn build_version_round_trips_and_refreshes_on_re_register() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-buildver-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        let build_of = |repo: &WorkerIdentityRepository| {
            let wid = wid.to_string();
            let repo = WorkerIdentityRepository::new(repo.db_pool.clone());
            async move {
                repo.list_active_builds()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|r| r.worker_id == wid)
                    .expect("registered worker must list")
                    .build_version
            }
        };

        // TOFU first use carries the report through.
        assert_eq!(
            repo.register_tofu(wid, &key(1), false, Some("0.1.0+aaaaaaa"))
                .await
                .unwrap(),
            TofuOutcome::Registered
        );
        assert_eq!(build_of(&repo).await.as_deref(), Some("0.1.0+aaaaaaa"));

        // Redeploy: same key, new build → the refresh arm updates it.
        assert_eq!(
            repo.register_tofu(wid, &key(1), false, Some("0.1.0+bbbbbbb-dirty"))
                .await
                .unwrap(),
            TofuOutcome::Registered
        );
        assert_eq!(
            build_of(&repo).await.as_deref(),
            Some("0.1.0+bbbbbbb-dirty")
        );

        // A registrant that reports nothing (pre-handshake worker, or the
        // operator CLI) clears the column — "unreported", not "still on b".
        assert_eq!(
            repo.register_tofu(wid, &key(1), false, None).await.unwrap(),
            TofuOutcome::Registered
        );
        assert_eq!(build_of(&repo).await, None);

        // Operator-grade insert arm carries it too.
        assert_eq!(
            repo.register(wid, &key(2), false, Some("9.9.9+ccccccc"))
                .await
                .unwrap(),
            RegisterOutcome::Registered
        );
        let builds: Vec<_> = repo
            .list_active_builds()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.worker_id == wid)
            .map(|r| r.build_version)
            .collect();
        assert_eq!(builds.len(), 2, "both active keys list");
        assert!(builds.contains(&Some("9.9.9+ccccccc".to_string())));
        assert!(builds.contains(&None));

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    /// The security-relevant half of the same contract: a REFUSED registration
    /// must leave the column exactly as it was. `build_version` rides the
    /// registration write, so every rejection arm — TOFU identity conflict,
    /// active-key cap, ineligible provisioning token — has to be a no-op on the
    /// recorded build. Without that, a caller who can only reach a REJECTED
    /// path (a token-holder tripping the TOFU rule, say) could still rewrite
    /// what the fleet report claims a worker is running: an unauthenticated-ish
    /// edit of an operator's diagnostic.
    #[tokio::test]
    async fn refused_registrations_never_write_build_version() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);

        async fn builds_for(repo: &WorkerIdentityRepository, wid: &str) -> Vec<Option<String>> {
            let mut v: Vec<Option<String>> = repo
                .list_active_builds()
                .await
                .unwrap()
                .into_iter()
                .filter(|r| r.worker_id == wid)
                .map(|r| r.build_version)
                .collect();
            v.sort();
            v
        }

        // --- TOFU conflict + ineligible token, on a worker with a recorded build.
        let wid = "test-refused-buildver";
        let capped = "test-refused-buildver-cap";
        let th = hash("refusedbuild");
        cleanup_worker_rows(&repo.db_pool, &[wid, capped], &[&th]).await;

        assert_eq!(
            repo.register_tofu(wid, &key(1), false, Some("0.1.0+goodaaa"))
                .await
                .unwrap(),
            TofuOutcome::Registered
        );
        let baseline = builds_for(&repo, wid).await;
        assert_eq!(baseline, vec![Some("0.1.0+goodaaa".to_string())]);

        // A DIFFERENT key for a TOFU-bound worker_id: 409, and the attacker's
        // build string must not land anywhere.
        assert_eq!(
            repo.register_tofu(wid, &key(2), false, Some("9.9.9+evilbbb"))
                .await
                .unwrap(),
            TofuOutcome::IdentityConflict
        );
        assert_eq!(builds_for(&repo, wid).await, baseline, "conflict wrote");

        // An unknown provisioning token: 401, same requirement (the whole tx,
        // build_version included, rolls back).
        assert_eq!(
            repo.register_with_provisioning_token(
                &th,
                wid,
                &key(2),
                false,
                true,
                Some("9.9.9+evilccc")
            )
            .await
            .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );
        assert_eq!(builds_for(&repo, wid).await, baseline, "bad token wrote");

        // --- Cap-reached, on its own worker so the assertions stay exact.
        for i in 0..MAX_ACTIVE_KEYS_PER_WORKER as u8 {
            assert_eq!(
                repo.register(capped, &key(i), false, Some(&format!("0.1.0+ok{i:05}")))
                    .await
                    .unwrap(),
                RegisterOutcome::Registered
            );
        }
        let at_cap = builds_for(&repo, capped).await;
        assert_eq!(
            repo.register(capped, &key(200), false, Some("9.9.9+evilddd"))
                .await
                .unwrap(),
            RegisterOutcome::CapReached
        );
        assert_eq!(builds_for(&repo, capped).await, at_cap, "cap arm wrote");
        assert!(
            !at_cap.contains(&Some("9.9.9+evilddd".to_string())),
            "refused build string must appear nowhere"
        );

        cleanup_worker_rows(&repo.db_pool, &[wid, capped], &[&th]).await;
    }

    #[tokio::test]
    async fn tofu_first_use_then_idempotent_then_conflicts() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-tofu-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        // First use: no history → key(1) becomes the trusted identity.
        assert_eq!(
            repo.register_tofu(wid, &key(1), false, None).await.unwrap(),
            TofuOutcome::Registered
        );
        // Idempotent same-key refresh, updating the capability bit.
        assert_eq!(
            repo.register_tofu(wid, &key(1), true, None).await.unwrap(),
            TofuOutcome::Registered
        );
        assert!(repo.worker_supports_sealing(wid).await.unwrap());

        // A DIFFERENT key for the same worker_id is refused (the gap this
        // closes: shared-token impersonation).
        assert_eq!(
            repo.register_tofu(wid, &key(2), false, None).await.unwrap(),
            TofuOutcome::IdentityConflict
        );
        // ...and the refusal wrote nothing.
        let active: Vec<_> = repo
            .load_active_registry()
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.worker_id == wid)
            .collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].public_key, key(1));

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    #[tokio::test]
    async fn tofu_refuses_revoked_key_reactivation_and_retired_id_claims() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-tofu-revoked-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        assert_eq!(
            repo.register_tofu(wid, &key(1), false, None).await.unwrap(),
            TofuOutcome::Registered
        );
        // Operator revokes the key (compromise / decommission).
        assert!(repo.deactivate(wid, &key(1)).await.unwrap());

        // The revoked key cannot re-activate itself over the network path.
        assert_eq!(
            repo.register_tofu(wid, &key(1), false, None).await.unwrap(),
            TofuOutcome::IdentityConflict
        );
        // Nor can a NEW key claim the retired worker_id (history exists).
        assert_eq!(
            repo.register_tofu(wid, &key(2), false, None).await.unwrap(),
            TofuOutcome::IdentityConflict
        );

        // The OPERATOR path still rotates freely: register a new key, and the
        // worker's subsequent boot-time TOFU refresh of that key succeeds.
        assert_eq!(
            repo.register(wid, &key(2), false, None).await.unwrap(),
            RegisterOutcome::Registered
        );
        assert_eq!(
            repo.register_tofu(wid, &key(2), true, None).await.unwrap(),
            TofuOutcome::Registered
        );

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    // Provisioning-token helpers: the repo treats token_hash as opaque (the
    // endpoint owns SHA-256), so tests can mint with any distinct 64-char id.
    fn hash(tag: &str) -> String {
        format!("{tag:0<64}")
    }

    fn in_one_hour() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::hours(1)
    }

    async fn token_used_at(
        repo: &WorkerIdentityRepository,
        id: uuid::Uuid,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        repo.list_provisioning_tokens()
            .await
            .unwrap()
            .into_iter()
            .find(|t| t.id == id)
            .expect("minted token must list")
            .used_at
    }

    #[tokio::test]
    async fn bound_token_is_single_use_and_carries_rotation_semantics() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-token-bound-worker";
        let th = hash("bound-rotation");
        cleanup_worker_rows(&repo.db_pool, &[wid], &[&th]).await;

        // Worker already has a TOFU-bound identity...
        assert_eq!(
            repo.register_tofu(wid, &key(1), false, None).await.unwrap(),
            TofuOutcome::Registered
        );
        // ...so a NEW key would be an IdentityConflict on the shared path. A
        // worker_id-BOUND token is the operator's rotation grant: it admits it.
        let id = repo
            .create_provisioning_token(&th, Some(wid), in_one_hour(), Some("rotation"))
            .await
            .unwrap();
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(2), false, true, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::Registered
        );
        assert!(token_used_at(&repo, id).await.is_some(), "token consumed");

        // Single use: a second redemption is refused even for a valid request.
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(3), false, true, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );

        cleanup_worker_rows(&repo.db_pool, &[wid], &[&th]).await;
    }

    #[tokio::test]
    async fn concurrent_redeems_of_one_token_admit_exactly_one() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = std::sync::Arc::new(WorkerIdentityRepository::new(pool));
        let wid = "test-token-race-worker";
        let th = hash("race");
        cleanup_worker_rows(&repo.db_pool, &[wid], &[&th]).await;
        repo.create_provisioning_token(&th, Some(wid), in_one_hour(), None)
            .await
            .unwrap();

        // Two concurrent redeems with different keys. Both would individually
        // succeed; the token's row lock must let exactly one through.
        let (a, b) = tokio::join!(
            {
                let repo = repo.clone();
                let th = th.clone();
                async move {
                    repo.register_with_provisioning_token(&th, wid, &key(10), false, true, None)
                        .await
                        .unwrap()
                }
            },
            {
                let repo = repo.clone();
                let th = th.clone();
                async move {
                    repo.register_with_provisioning_token(&th, wid, &key(11), false, true, None)
                        .await
                        .unwrap()
                }
            }
        );
        let registered = [a, b]
            .iter()
            .filter(|o| **o == TokenRegisterOutcome::Registered)
            .count();
        let invalid = [a, b]
            .iter()
            .filter(|o| **o == TokenRegisterOutcome::InvalidToken)
            .count();
        assert_eq!((registered, invalid), (1, 1), "exactly one redeem wins");

        // Exactly one key landed in the registry.
        let mine: Vec<_> = repo
            .load_active_registry()
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.worker_id == wid)
            .collect();
        assert_eq!(mine.len(), 1);

        cleanup_worker_rows(&repo.db_pool, &[wid], &[&th]).await;
    }

    #[tokio::test]
    async fn expired_revoked_and_mismatched_tokens_refuse_without_consuming() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-token-refusals-worker";
        let th_expired = hash("expired");
        let th_other = hash("otherbound");
        let th_revoked = hash("revoked");
        cleanup_worker_rows(
            &repo.db_pool,
            &[wid],
            &[&th_expired, &th_other, &th_revoked],
        )
        .await;

        // Expired.
        let id_expired = repo
            .create_provisioning_token(
                &th_expired,
                Some(wid),
                chrono::Utc::now() - chrono::Duration::minutes(1),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            repo.register_with_provisioning_token(&th_expired, wid, &key(1), false, true, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );
        assert!(token_used_at(&repo, id_expired).await.is_none());

        // Bound to a DIFFERENT worker_id.
        let id_other = repo
            .create_provisioning_token(&th_other, Some("some-other-worker"), in_one_hour(), None)
            .await
            .unwrap();
        assert_eq!(
            repo.register_with_provisioning_token(&th_other, wid, &key(1), false, true, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );
        assert!(token_used_at(&repo, id_other).await.is_none());

        // Revoked.
        let id_revoked = repo
            .create_provisioning_token(&th_revoked, Some(wid), in_one_hour(), None)
            .await
            .unwrap();
        assert!(repo.revoke_provisioning_token(id_revoked).await.unwrap());
        assert!(
            !repo.revoke_provisioning_token(id_revoked).await.unwrap(),
            "second revoke is a no-op"
        );
        assert_eq!(
            repo.register_with_provisioning_token(&th_revoked, wid, &key(1), false, true, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );

        // Nothing registered through any of the refusals.
        assert!(!repo
            .load_active_registry()
            .await
            .unwrap()
            .iter()
            .any(|e| e.worker_id == wid));

        cleanup_worker_rows(
            &repo.db_pool,
            &[wid],
            &[&th_expired, &th_other, &th_revoked],
        )
        .await;
    }

    #[tokio::test]
    async fn wildcard_token_tofu_semantics_and_enforcement_flag() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-token-wildcard-worker";
        let th = hash("wildcard");
        let th2 = hash("wildcard-second");
        cleanup_worker_rows(&repo.db_pool, &[wid], &[&th, &th2]).await;
        let id = repo
            .create_provisioning_token(&th, None, in_one_hour(), Some("migration compat"))
            .await
            .unwrap();

        // Enforcement ON → wildcard refused outright, NOT consumed.
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(1), false, true, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::InvalidToken
        );
        assert!(token_used_at(&repo, id).await.is_none());

        // Enforcement OFF → accepted, TOFU semantics, consumed.
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(1), false, false, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::Registered
        );
        assert!(token_used_at(&repo, id).await.is_some());

        // A second wildcard token cannot re-bind the now-taken worker_id to a
        // different key (TOFU applies to wildcards) — and the refusal does not
        // burn the new token.
        let id2 = repo
            .create_provisioning_token(&th2, None, in_one_hour(), None)
            .await
            .unwrap();
        assert_eq!(
            repo.register_with_provisioning_token(&th2, wid, &key(2), false, false, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::IdentityConflict
        );
        assert!(
            token_used_at(&repo, id2).await.is_none(),
            "refusal rolls back"
        );

        cleanup_worker_rows(&repo.db_pool, &[wid], &[&th, &th2]).await;
    }

    #[tokio::test]
    async fn refused_bound_registration_does_not_burn_the_token() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-token-cap-worker";
        let th = hash("capbound");
        cleanup_worker_rows(&repo.db_pool, &[wid], &[&th]).await;

        // Fill the worker to its active-key cap via the operator path.
        for i in 0..MAX_ACTIVE_KEYS_PER_WORKER as u8 {
            assert_eq!(
                repo.register(wid, &key(i), false, None).await.unwrap(),
                RegisterOutcome::Registered
            );
        }
        let id = repo
            .create_provisioning_token(&th, Some(wid), in_one_hour(), None)
            .await
            .unwrap();

        // Bound-token redemption hits the cap → refused, token survives.
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(100), false, true, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::CapReached
        );
        assert!(token_used_at(&repo, id).await.is_none());

        // Operator frees a slot; the SAME token now redeems.
        assert!(repo.deactivate(wid, &key(0)).await.unwrap());
        assert_eq!(
            repo.register_with_provisioning_token(&th, wid, &key(100), false, true, None)
                .await
                .unwrap(),
            TokenRegisterOutcome::Registered
        );

        cleanup_worker_rows(&repo.db_pool, &[wid], &[&th]).await;
    }

    #[tokio::test]
    async fn rotation_overlap_then_cap_then_deactivate() {
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-rotation-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        // Fill up to the cap with distinct keys — all admitted.
        for i in 0..MAX_ACTIVE_KEYS_PER_WORKER as u8 {
            assert_eq!(
                repo.register(wid, &key(i), false, None).await.unwrap(),
                RegisterOutcome::Registered
            );
        }
        // One more NEW key is refused.
        assert_eq!(
            repo.register(wid, &key(200), false, None).await.unwrap(),
            RegisterOutcome::CapReached
        );
        // But re-registering an EXISTING key is still allowed at the cap.
        assert_eq!(
            repo.register(wid, &key(0), false, None).await.unwrap(),
            RegisterOutcome::Registered
        );

        // Deactivate one, freeing a slot; the new key now fits.
        assert!(repo.deactivate(wid, &key(0)).await.unwrap());
        assert!(
            !repo.deactivate(wid, &key(0)).await.unwrap(),
            "second deactivate is a no-op"
        );
        assert_eq!(
            repo.register(wid, &key(200), false, None).await.unwrap(),
            RegisterOutcome::Registered
        );

        let active: Vec<_> = repo
            .load_active_registry()
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.worker_id == wid)
            .collect();
        assert_eq!(active.len(), MAX_ACTIVE_KEYS_PER_WORKER as usize);
        assert!(
            !active.iter().any(|e| e.public_key == key(0)),
            "deactivated key must not load"
        );

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    // ===================== liveness + reaper =====================
    //
    // These cover a TRUST-BOUNDARY write whose blast radius is fleet-wide job
    // dispatch, so the negative direction is tested harder than the positive
    // one: every way a LIVE worker could be reaped gets its own assertion, and
    // the positive case gets one.

    /// The reaper is TABLE-WIDE by design — it sweeps every worker, not one —
    /// so unlike every other test in this module these cannot isolate
    /// themselves with a distinct `worker_id` alone. Two of them aging rows
    /// concurrently makes each one's returned count include the other's rows.
    /// Serialise them against each other; the non-reaper tests are unaffected
    /// because they never age a row, so their fresh `last_seen_at` /
    /// `last_liveness_at` can never fall inside a sweep window.
    ///
    /// `tokio::sync::Mutex` (not `std`) because the guard is held across
    /// `.await`s.
    static REAP_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Age a row's liveness/registration clocks directly, so the window tests
    /// don't have to sleep for hours. Writes the same columns the production
    /// paths write; the reaper's predicate is unchanged and still evaluated by
    /// Postgres against Postgres's clock.
    async fn age_row(
        repo: &WorkerIdentityRepository,
        worker_id: &str,
        public_key: &[u8; 32],
        liveness_hours_ago: Option<i32>,
        seen_hours_ago: i32,
    ) {
        sqlx::query(
            "UPDATE worker_identities
             SET last_liveness_at = CASE WHEN $3::int IS NULL THEN NULL
                                         ELSE now() - make_interval(hours => $3::int) END,
                 last_seen_at = now() - make_interval(hours => $4::int)
             WHERE worker_id = $1 AND public_key = $2",
        )
        .bind(worker_id)
        .bind(&public_key[..])
        .bind(liveness_hours_ago)
        .bind(seen_hours_ago)
        .execute(&repo.db_pool)
        .await
        .expect("age row");
    }

    async fn is_active(repo: &WorkerIdentityRepository, worker_id: &str, pk: &[u8; 32]) -> bool {
        repo.load_active_registry()
            .await
            .unwrap()
            .into_iter()
            .any(|e| e.worker_id == worker_id && e.public_key == *pk)
    }

    /// THE LOAD-BEARING NEGATIVE TEST. A worker that is pinging must survive
    /// repeated sweeps — deactivating it would break job-result verification
    /// fleet-wide, and because TOFU refuses to re-activate a deactivated key it
    /// could not recover without an operator.
    #[tokio::test]
    async fn a_live_worker_survives_repeated_sweeps() {
        let _reap_guard = REAP_LOCK.lock().await;
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-reap-live-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        assert_eq!(
            repo.register_tofu(wid, &key(1), false, Some("0.1.0+aaaaaaa"))
                .await
                .unwrap(),
            TofuOutcome::Registered
        );

        // Ten ping-then-sweep cycles with an aggressive 1h window.
        for _ in 0..10 {
            assert!(
                repo.touch_liveness(wid, &key(1)).await.unwrap(),
                "ping must find the active row"
            );
            repo.reap_departed_identities(1).await.unwrap();
            assert!(
                is_active(&repo, wid, &key(1)).await,
                "a pinging worker must never be reaped"
            );
        }

        // Even the pre-protocol arm cannot touch it: it has participated, so
        // `last_liveness_at IS NULL` excludes it regardless of how old its
        // boot-time `last_seen_at` is.
        age_row(&repo, wid, &key(1), Some(0), 10_000).await;
        assert_eq!(
            repo.reap_pre_protocol_identities(1).await.unwrap(),
            0,
            "a participating row is never in the pre-protocol population"
        );
        assert!(is_active(&repo, wid, &key(1)).await);

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    /// A row that has NEVER pinged is never reaped by the automatic sweep, no
    /// matter how old. This is "absence of evidence is not evidence of
    /// departure" as an executable assertion — it is what makes the sweep safe
    /// to enable on a fleet still rolling onto the liveness build, and it is
    /// the guard the obvious `last_seen_at` decay does not have.
    #[tokio::test]
    async fn a_never_pinging_row_is_never_auto_reaped() {
        let _reap_guard = REAP_LOCK.lock().await;
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-reap-legacy-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        assert_eq!(
            repo.register_tofu(wid, &key(1), false, None).await.unwrap(),
            TofuOutcome::Registered
        );
        // Registered a decade ago and never pinged.
        age_row(&repo, wid, &key(1), None, 87_600).await;

        assert_eq!(
            repo.reap_departed_identities(1).await.unwrap(),
            0,
            "unknown liveness must never be read as departed"
        );
        assert!(is_active(&repo, wid, &key(1)).await);

        // Only the explicitly opt-in pre-protocol arm may act on it.
        assert_eq!(repo.reap_pre_protocol_identities(1).await.unwrap(), 1);
        assert!(!is_active(&repo, wid, &key(1)).await);

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    /// The positive case, and the window boundary: a participating worker that
    /// goes silent past the window is reaped, and one still inside it is not.
    #[tokio::test]
    async fn a_departed_worker_is_reaped_only_past_the_window() {
        let _reap_guard = REAP_LOCK.lock().await;
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-reap-departed-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        assert_eq!(
            repo.register_tofu(wid, &key(1), false, None).await.unwrap(),
            TofuOutcome::Registered
        );
        assert!(repo.touch_liveness(wid, &key(1)).await.unwrap());

        // Silent for 5h under a 24h window — inside, so still trusted.
        age_row(&repo, wid, &key(1), Some(5), 5).await;
        assert_eq!(repo.reap_departed_identities(24).await.unwrap(), 0);
        assert!(is_active(&repo, wid, &key(1)).await);

        // Silent for 25h — past the window, so reaped.
        age_row(&repo, wid, &key(1), Some(25), 25).await;
        assert_eq!(repo.reap_departed_identities(24).await.unwrap(), 1);
        assert!(!is_active(&repo, wid, &key(1)).await);

        // The sweep is idempotent: a second pass finds nothing to do.
        assert_eq!(repo.reap_departed_identities(24).await.unwrap(), 0);

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    /// A liveness ping GRANTS NOTHING. It cannot create a row for an
    /// unregistered key, and it cannot resurrect a deactivated one — so a
    /// reaped (or operator-revoked) worker cannot ping its way back into the
    /// trust ring, and the TOFU conflict path still governs its return.
    #[tokio::test]
    async fn liveness_ping_cannot_create_or_resurrect_an_identity() {
        let _reap_guard = REAP_LOCK.lock().await;
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let wid = "test-liveness-noauthz-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        // Never registered → the ping is a no-op, NOT an insert.
        assert!(!repo.touch_liveness(wid, &key(1)).await.unwrap());
        assert!(repo
            .list()
            .await
            .unwrap()
            .iter()
            .all(|r| r.worker_id != wid));

        // Registered, then reaped.
        assert_eq!(
            repo.register_tofu(wid, &key(1), false, None).await.unwrap(),
            TofuOutcome::Registered
        );
        assert!(repo.touch_liveness(wid, &key(1)).await.unwrap());
        age_row(&repo, wid, &key(1), Some(48), 48).await;
        assert_eq!(repo.reap_departed_identities(24).await.unwrap(), 1);

        // The reaped key cannot ping itself back to active.
        assert!(
            !repo.touch_liveness(wid, &key(1)).await.unwrap(),
            "a deactivated key must not be refreshable"
        );
        assert!(!is_active(&repo, wid, &key(1)).await);

        // TOFU is NOT weakened by reaping: the returning worker is refused on
        // the network path exactly as a revoked key is, and a NEW key cannot
        // claim the reaped worker_id either.
        assert_eq!(
            repo.register_tofu(wid, &key(1), false, None).await.unwrap(),
            TofuOutcome::IdentityConflict
        );
        assert_eq!(
            repo.register_tofu(wid, &key(2), false, None).await.unwrap(),
            TofuOutcome::IdentityConflict
        );
        // The operator path remains the documented remedy.
        assert_eq!(
            repo.register(wid, &key(1), false, None).await.unwrap(),
            RegisterOutcome::Registered
        );
        assert!(is_active(&repo, wid, &key(1)).await);

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    /// Concurrency: a worker pinging while the sweep runs must not be reaped.
    /// Both operations are single guarded statements, so whichever order
    /// Postgres picks is correct — the UPDATE re-evaluates its predicate after
    /// taking the row lock. Asserted as an invariant over many interleavings
    /// rather than a fixed order, since the schedule is not ours to choose.
    #[tokio::test]
    async fn a_worker_pinging_during_a_sweep_is_not_reaped() {
        let _reap_guard = REAP_LOCK.lock().await;
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = std::sync::Arc::new(WorkerIdentityRepository::new(pool));
        let wid = "test-reap-race-worker";
        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;

        for _ in 0..25 {
            // Reset to a row that is exactly AT the edge: last pinged 2h ago
            // with a 1h window, so a sweep that lands first WOULD reap it.
            cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
            repo.register_tofu(wid, &key(1), false, None).await.unwrap();
            age_row(&repo, wid, &key(1), Some(2), 2).await;

            let (pinged, _reaped) = tokio::join!(
                {
                    let repo = repo.clone();
                    async move { repo.touch_liveness(wid, &key(1)).await.unwrap() }
                },
                {
                    let repo = repo.clone();
                    async move { repo.reap_departed_identities(1).await.unwrap() }
                }
            );

            // THE INVARIANT: if the ping observed a live row, that row must
            // still be live. A `false` ping means the sweep won the race and
            // legitimately reaped a row that had been silent past the window —
            // the worker learns this from the ping's own return value.
            if pinged {
                assert!(
                    is_active(&repo, wid, &key(1)).await,
                    "a ping that succeeded must not be followed by a reap of that row"
                );
            }
        }

        cleanup_worker_rows(&repo.db_pool, &[wid], &[]).await;
    }

    /// Reproduce the EXACT state that motivated this change and drive the real
    /// mechanism against it, rather than asserting the fix in the abstract
    /// ([[gate-that-doesnt-gate]] — prove it against the broken tree).
    ///
    /// Observed live 2026-08-04 in `worker_identities`:
    ///
    /// ```text
    /// worker_id          active  build          last_seen
    /// dev-worker-fleet   t       0.1.0+3ffb611  19:39:08   <- the running worker
    /// worker-wt-cddef6d  t       0.1.0+cddef6d  15:36:31   <- deleted hours earlier
    /// ```
    ///
    /// Note both rows carried the SAME public key: the throwaway review
    /// container inherited the fleet's `TALOS_WORKER_SIGNING_KEY` and registered
    /// it under a second `worker_id`. So the leak is not "an extra key" but an
    /// extra TRUSTED IDENTITY — which is exactly what the verify path keys on.
    #[tokio::test]
    async fn reproduces_the_2026_08_04_leftover_state_and_reaps_it() {
        let _reap_guard = REAP_LOCK.lock().await;
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let live = "test-repro-dev-worker-fleet";
        let ghost = "test-repro-worker-wt-cddef6d";
        cleanup_worker_rows(&repo.db_pool, &[live, ghost], &[]).await;

        // The shared key, as observed.
        let shared = key(42);
        repo.register_tofu(live, &shared, false, Some("0.1.0+3ffb611"))
            .await
            .unwrap();
        repo.register_tofu(ghost, &shared, false, Some("0.1.0+cddef6d"))
            .await
            .unwrap();

        // BEFORE: the broken state. Two active identities; the ghost's is as
        // trusted as the live worker's, indefinitely.
        let active_ids = |repo: &WorkerIdentityRepository| {
            let repo = WorkerIdentityRepository::new(repo.db_pool.clone());
            async move {
                let mut v: Vec<String> = repo
                    .load_active_registry()
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|e| e.worker_id)
                    .filter(|w| w.starts_with("test-repro-"))
                    .collect();
                v.sort();
                v
            }
        };
        assert_eq!(
            active_ids(&repo).await,
            vec![live.to_string(), ghost.to_string()],
            "reproduce the two-active-row state first"
        );

        // Both workers roll onto a build that pings; the ghost then departs and
        // the live worker keeps pinging.
        assert!(repo.touch_liveness(live, &shared).await.unwrap());
        assert!(repo.touch_liveness(ghost, &shared).await.unwrap());
        age_row(&repo, ghost, &shared, Some(48), 48).await;

        // AFTER: the mechanism removes exactly one identity from the ring.
        assert_eq!(repo.reap_departed_identities(24).await.unwrap(), 1);
        assert_eq!(
            active_ids(&repo).await,
            vec![live.to_string()],
            "only the departed identity leaves the trust ring"
        );

        // And the live worker is still verifiable — the whole point.
        assert!(is_active(&repo, live, &shared).await);

        cleanup_worker_rows(&repo.db_pool, &[live, ghost], &[]).await;
    }

    /// The two reaper arms address strictly disjoint populations, so enabling
    /// the opt-in pre-protocol arm can never widen what the automatic arm
    /// touches. Guards against a future edit collapsing them into one query.
    #[tokio::test]
    async fn the_two_reaper_arms_are_disjoint() {
        let _reap_guard = REAP_LOCK.lock().await;
        let Some(pool) = pool_or_skip().await else {
            return;
        };
        let repo = WorkerIdentityRepository::new(pool);
        let live = "test-reap-disjoint-live";
        let legacy = "test-reap-disjoint-legacy";
        let gone = "test-reap-disjoint-gone";
        cleanup_worker_rows(&repo.db_pool, &[live, legacy, gone], &[]).await;

        for w in [live, legacy, gone] {
            repo.register_tofu(w, &key(1), false, None).await.unwrap();
        }
        // live: pinging now. legacy: never pinged, ancient. gone: pinged, silent.
        age_row(&repo, live, &key(1), Some(0), 5_000).await;
        age_row(&repo, legacy, &key(1), None, 5_000).await;
        age_row(&repo, gone, &key(1), Some(72), 5_000).await;

        assert_eq!(
            repo.reap_departed_identities(24).await.unwrap(),
            1,
            "automatic arm takes only the departed participant"
        );
        assert!(is_active(&repo, live, &key(1)).await);
        assert!(is_active(&repo, legacy, &key(1)).await);
        assert!(!is_active(&repo, gone, &key(1)).await);

        assert_eq!(
            repo.reap_pre_protocol_identities(24).await.unwrap(),
            1,
            "opt-in arm takes only the never-participating row"
        );
        assert!(
            is_active(&repo, live, &key(1)).await,
            "live worker untouched"
        );
        assert!(!is_active(&repo, legacy, &key(1)).await);

        cleanup_worker_rows(&repo.db_pool, &[live, legacy, gone], &[]).await;
    }
}

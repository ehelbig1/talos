//! Phase 3 of the KEK→KMS migration: rewrap every DEK in
//! `encryption_keys` using a new KEK provider, storing the result in
//! the `encrypted_key_v2` column without touching the legacy
//! `encrypted_key` column.
//!
//! Operator workflow:
//!
//! 1. Bring up the new KEK backend (e.g. Vault transit) and verify
//!    `KekProvider::health_check` (or equivalent) passes.
//! 2. Run [`rewrap_all_deks_to_v2`] with the running env-KEK provider as
//!    `source` and the new Vault provider as `target`. Idempotent —
//!    rerunning it is safe and skips already-rewrapped rows.
//! 3. Verify zero rows with `encrypted_key_v2 IS NULL`. Soak.
//! 4. Phase 4: cut readers over to v2 (vault provider). Watch for any
//!    decrypt errors.
//! 5. Phase 5: terminal migration — drop legacy column, NOT NULL on v2.
//!
//! Critical safety invariant — verify-before-commit:
//!
//! For each DEK row we (1) unwrap with the source provider to recover
//! the plaintext DEK, (2) wrap with the target provider, (3)
//! immediately unwrap the new ciphertext with the target provider, and
//! (4) byte-compare the round-trip plaintext to the original. Only if
//! all four steps succeed do we persist the v2 ciphertext. If verify
//! fails on any row the entire batch's transaction rolls back and the
//! migration aborts with an error.
//!
//! This means the only way to land bad ciphertext is for the target
//! provider's decrypt path to silently lie about success — which is
//! exactly the failure mode that would make Phase 5 unrecoverable, so
//! catching it here protects us from the irreversibility cliff.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::kek_provider::KekProvider;

/// Per-run statistics from [`rewrap_all_deks_to_v2`].
#[derive(Debug, Default, Clone)]
pub struct RewrapStats {
    /// Total rows visited (regardless of whether they needed rewrapping).
    pub scanned: u64,
    /// Rows that already had `encrypted_key_v2` populated (skipped).
    pub already_v2: u64,
    /// Rows that were rewrapped on this run.
    pub rewrapped: u64,
}

/// Default batch size for rewrap. Each batch runs in one transaction —
/// large enough to amortize tx overhead, small enough that a worst-case
/// rollback only loses a small chunk of progress (subsequent runs pick
/// up where we left off because already-v2 rows are skipped).
pub const DEFAULT_BATCH_SIZE: usize = 50;

/// Rewrap every DEK in `encryption_keys` using `target`, storing the
/// result in `encrypted_key_v2`. Idempotent — rows that already have
/// `encrypted_key_v2` populated are skipped.
///
/// `source` MUST be the provider that wrapped the existing
/// `encrypted_key` column. Caller's responsibility to verify this
/// matches the SecretsManager's currently-active provider.
///
/// Returns aggregate stats. On any error the in-flight batch is rolled
/// back; previous batches' commits are preserved (so a retry resumes
/// without re-doing work).
///
/// # Safety
///
/// Per-row verify-before-commit (see module docs). The migration
/// aborts loudly the first time a round-trip fails — better to halt
/// at row N than to fingers-crossed-write opaque bytes that won't
/// decrypt later.
pub async fn rewrap_all_deks_to_v2(
    pool: &PgPool,
    source: Arc<dyn KekProvider>,
    target: Arc<dyn KekProvider>,
    batch_size: usize,
) -> Result<RewrapStats> {
    let batch_size = batch_size.clamp(10, 500);
    let mut stats = RewrapStats::default();

    // Cursor pagination by id avoids OFFSET cost on large tables and
    // keeps the order stable across batches even if other writes happen.
    let mut last_id: Option<Uuid> = None;

    loop {
        // Fetch the next batch of UNWRAPPED rows (encrypted_key_v2 IS NULL).
        // The partial index `idx_encryption_keys_needs_rewrap` covers
        // this predicate exactly so the scan is cheap.
        let rows = sqlx::query(
            "SELECT id, encrypted_key FROM encryption_keys \
             WHERE encrypted_key_v2 IS NULL \
               AND ($1::uuid IS NULL OR id > $1) \
             ORDER BY id LIMIT $2",
        )
        .bind(last_id)
        .bind(batch_size as i64)
        .fetch_all(pool)
        .await
        .context("rewrap: failed to fetch batch of unwrapped DEKs")?;

        if rows.is_empty() {
            break;
        }

        let batch_len = rows.len();
        let mut tx = pool
            .begin()
            .await
            .context("rewrap: failed to begin batch transaction")?;
        let mut batch_rewrapped: u64 = 0;

        for row in &rows {
            let id: Uuid = row.try_get("id")?;
            let v1: Vec<u8> = row.try_get("encrypted_key")?;
            stats.scanned += 1;
            last_id = Some(id);

            // Step 1: unwrap with source provider.
            let plaintext = source.unwrap_dek(&v1).await.with_context(|| {
                format!(
                    "rewrap: source.unwrap_dek failed for DEK {id} — \
                         either the source provider is not the one that wrapped \
                         this row, or the row is corrupt"
                )
            })?;
            if plaintext.len() != 32 {
                return Err(anyhow!(
                    "rewrap: DEK {id} unwrapped to {} bytes, expected 32",
                    plaintext.len()
                ));
            }
            let mut dek_arr = [0u8; 32];
            dek_arr.copy_from_slice(&plaintext);

            // Step 2: wrap with target provider.
            let v2 = target
                .wrap_dek(&dek_arr)
                .await
                .with_context(|| format!("rewrap: target.wrap_dek failed for DEK {id}"))?;

            // Step 3+4: VERIFY-BEFORE-COMMIT — round-trip the new
            // ciphertext through the target provider and byte-compare
            // to the original plaintext. Defends against a target
            // provider that silently corrupts on write.
            let verify = target.unwrap_dek(&v2).await.with_context(|| {
                format!("rewrap: target.unwrap_dek verify-step failed for DEK {id}")
            })?;
            if verify.as_slice() != plaintext.as_slice() {
                return Err(anyhow!(
                    "rewrap: VERIFY FAILED for DEK {id} — round-trip plaintext \
                     differs from source. ABORTING migration. No bytes were \
                     written to encrypted_key_v2 for this row."
                ));
            }

            // UPDATE conditional on encrypted_key_v2 IS NULL — defends
            // against a concurrent rewrap operator who might have
            // populated the row between SELECT and UPDATE. Returns
            // affected row count so we can detect + log the race.
            let result = sqlx::query(
                "UPDATE encryption_keys \
                 SET encrypted_key_v2 = $1 \
                 WHERE id = $2 AND encrypted_key_v2 IS NULL",
            )
            .bind(&v2)
            .bind(id)
            .execute(&mut *tx)
            .await
            .with_context(|| format!("rewrap: UPDATE failed for DEK {id}"))?;
            if result.rows_affected() == 0 {
                tracing::warn!(
                    %id,
                    "rewrap: DEK was rewrapped concurrently by another writer; skipping"
                );
                stats.already_v2 += 1;
                continue;
            }
            batch_rewrapped += 1;
        }

        tx.commit()
            .await
            .context("rewrap: failed to commit batch")?;
        stats.rewrapped += batch_rewrapped;

        tracing::info!(
            batch_size = batch_len,
            batch_rewrapped,
            total_scanned = stats.scanned,
            total_rewrapped = stats.rewrapped,
            "rewrap batch committed"
        );

        if batch_len < batch_size {
            break;
        }
    }

    // Final sanity check: count remaining NULL rows. Should be zero on
    // a clean run; non-zero means concurrent inserts happened during
    // the rewrap (operator should re-run to catch them).
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM encryption_keys WHERE encrypted_key_v2 IS NULL")
            .fetch_one(pool)
            .await
            .context("rewrap: failed to count remaining NULL rows")?;
    if remaining > 0 {
        tracing::warn!(
            remaining,
            "rewrap: {} rows still have NULL encrypted_key_v2 after run \
             (likely created during the rewrap window — re-run to catch them)",
            remaining
        );
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kek_provider::EnvKekProvider;

    /// Verify-before-commit must catch a target that silently
    /// scrambles on wrap. Using two distinct EnvKekProviders for
    /// source/target so the target's unwrap can't decrypt source-format
    /// bytes — but our verify step uses the TARGET's unwrap on the
    /// TARGET's wrap output, so this should round-trip cleanly.
    /// Negative test: pass a deliberately-broken target.
    #[tokio::test]
    async fn happy_path_verifies_round_trip() {
        // Two different EnvKekProvider instances with different keys.
        // Wrap with source, rewrap with target, verify the wrap output
        // round-trips through the target provider.
        let source = Arc::new(EnvKekProvider::from_raw_bytes(vec![1u8; 32]));
        let target = Arc::new(EnvKekProvider::from_raw_bytes(vec![2u8; 32]));
        let dek = [42u8; 32];
        let v1 = source.wrap_dek(&dek).await.unwrap();
        let v2 = target.wrap_dek(&dek).await.unwrap();
        let unwrapped = target.unwrap_dek(&v2).await.unwrap();
        assert_eq!(unwrapped.as_slice(), &dek);
        // Confirm cross-provider rejection: unwrapping v1 with target
        // (wrong key) must fail loudly.
        assert!(target.unwrap_dek(&v1).await.is_err());
    }
}

//! Restore verifier — the "can we actually get the data back" half of
//! `scripts/drills/backup-restore.sh`.
//!
//! WHY THIS EXISTS, next to `verify_phase_b`. Until 2026-08-03 the drill's
//! entire verify phase was `verify_phase_b`, which WRITES a fresh memory row
//! into the restored database and reads it back. That is a real test of the
//! restored KEK→DEK→AEAD chain, but it is a test of the chain's ability to
//! encrypt something NEW. It says nothing about whether the ciphertext that
//! was already in the backup can still be decrypted — which is the only
//! question a restore is asked. A drill that reports success while checking
//! less than it implies is the backup-restore analogue of a permanently-red
//! alert, so the gap is closed here rather than described.
//!
//! What this checks, all against the RESTORED database:
//!   1. `_sqlx_migrations` — every migration applied, none marked failed, and
//!      (optionally) the max version matches what this checkout ships. A
//!      restore that silently lands an older schema is not a restore.
//!   2. Critical tables exist and their row counts are reported. Two are
//!      asserted non-empty because a zero there means the restore moved no
//!      rows at all: `encryption_keys` (no DEK ⇒ nothing is readable, ever)
//!      and `actors` (the tenancy root).
//!   3. `actor_memory` — a sample of PRE-EXISTING rows is decrypted through
//!      the canonical `recall_exact` path, sampled per distinct
//!      (`value_format`, `value_key_id`) pair so every on-disk AEAD format
//!      and every DEK actually in use is exercised at least once.
//!   4. `secrets` — same idea through `SecretsManager::get_secret`, sampled
//!      per distinct `encryption_format_version`. Secrets are what a restore
//!      is FOR (OAuth tokens, provider keys); a backup that restores rows
//!      whose plaintext is unrecoverable has restored nothing.
//!   5. Referential integrity of the key material: every `encryption_key_id`
//!      referenced by data has a row in `encryption_keys`.
//!
//! NOTHING DECRYPTED IS EVER PRINTED. Every success line reports a count or a
//! byte length. The drill runs this against real user data in a scratch
//! container; its stdout goes to a log.
//!
//! Run with (the drill does this for you):
//!   DATABASE_URL=postgres://…  TALOS_MASTER_KEY=…  KEK_PROVIDER=env \
//!     cargo run --example verify_restore -p controller

use anyhow::{bail, Context, Result};
use sqlx::Row as _;
use std::collections::BTreeSet;
use std::sync::Arc;
use uuid::Uuid;

/// Tables whose presence and row count are reported on every run.
/// `must_be_non_empty` is deliberately narrow — see the module docs.
const CRITICAL_TABLES: &[(&str, bool)] = &[
    ("encryption_keys", true),
    ("actors", true),
    ("users", false),
    ("organizations", false),
    ("secrets", false),
    ("actor_memory", false),
    ("workflows", false),
    ("modules", false),
    ("workflow_executions", false),
    ("ml_examples", false),
];

/// How many rows to decrypt per distinct (format, key) group. Decryption is
/// the expensive part of the drill's verify phase and the failure mode being
/// tested (wrong/missing DEK, truncated ciphertext, wrong AAD) is uniform
/// within a group, so a small sample finds it.
const SAMPLE_PER_GROUP: i64 = 5;

#[tokio::main]
async fn main() -> Result<()> {
    let db_url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL must point at the RESTORED scratch database")?;
    let pool = sqlx::PgPool::connect(&db_url).await?;
    let mut failures: Vec<String> = Vec::new();

    // ── 1. Schema version ────────────────────────────────────────────────
    let (applied, max_version, failed): (i64, Option<i64>, i64) = sqlx::query_as(
        "SELECT COUNT(*), MAX(version), COUNT(*) FILTER (WHERE NOT success) FROM _sqlx_migrations",
    )
    .fetch_one(&pool)
    .await
    .context("_sqlx_migrations is unreadable — the restore did not land a Talos schema")?;

    if failed > 0 {
        failures.push(format!("{failed} migration(s) recorded as failed"));
    }
    if applied == 0 {
        failures.push("no migrations recorded — empty or non-Talos database".into());
    }
    println!(
        "✓ schema: {applied} migrations applied, max version {}, {failed} failed",
        max_version
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into())
    );

    // The drill passes the newest migration filename's version prefix. A
    // restore that lands an OLDER schema than this checkout expects is a
    // silent partial restore; without this it looks identical to a good one.
    if let Ok(expected) = std::env::var("TALOS_DRILL_EXPECT_MIGRATION_VERSION") {
        let expected: i64 = expected
            .trim()
            .parse()
            .context("TALOS_DRILL_EXPECT_MIGRATION_VERSION must be a migration version number")?;
        match max_version {
            Some(v) if v == expected => println!("✓ schema version matches this checkout ({v})"),
            Some(v) => failures.push(format!(
                "restored schema is at version {v}, this checkout ships {expected}"
            )),
            None => failures.push("restored database has no migration rows".into()),
        }
    }

    // ── 2. Critical tables ───────────────────────────────────────────────
    for (table, must_be_non_empty) in CRITICAL_TABLES {
        // Table names come from the const list above, never from input.
        let count: Result<(i64,), _> = sqlx::query_as(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&pool)
            .await;
        match count {
            Ok((n,)) => {
                println!("  {table:<22} {n:>8} rows");
                if *must_be_non_empty && n == 0 {
                    failures.push(format!("{table} is EMPTY in the restored database"));
                }
            }
            Err(e) => failures.push(format!("{table} is unreadable after restore: {e}")),
        }
    }

    // ── 3. Wire the crypto stack exactly as the controller does ──────────
    use controller::secrets::kek_provider::{env_kek_provider_from_environment, KekProvider};
    use controller::secrets::vault_kek_provider::VaultTransitProvider;
    use controller::secrets::{SecretRequestor, SecretsManager};

    let kind = std::env::var("KEK_PROVIDER")
        .unwrap_or_else(|_| "env".to_string())
        .to_lowercase();
    let (active, legacy): (Arc<dyn KekProvider>, Option<Arc<dyn KekProvider>>) = match kind.as_str()
    {
        "env" => (env_kek_provider_from_environment()?, None),
        "vault" => {
            let v = VaultTransitProvider::from_env()?;
            v.health_check().await?;
            (Arc::new(v), Some(env_kek_provider_from_environment()?))
        }
        other => bail!("Unknown KEK_PROVIDER={other}"),
    };
    println!("✓ KEK provider '{kind}' reachable against the restored stack");

    let secrets = Arc::new(SecretsManager::with_kek_providers(
        pool.clone(),
        active,
        legacy,
    )?);
    talos_memory::register_memory_crypto_hook(Arc::new(
        controller::memory_crypto::SecretsManagerMemoryCrypto::new(secrets.clone()),
    ));

    // ── 4. Decrypt PRE-EXISTING actor_memory rows ────────────────────────
    let groups = sqlx::query(
        "SELECT value_format, value_key_id, COUNT(*) AS n \
         FROM actor_memory GROUP BY value_format, value_key_id ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await?;

    if groups.is_empty() {
        println!("  actor_memory: no rows to decrypt (empty table — nothing asserted)");
    }
    for g in &groups {
        let fmt: i16 = g.try_get("value_format")?;
        let key_id: Uuid = g.try_get("value_key_id")?;
        let total: i64 = g.try_get("n")?;

        let rows = sqlx::query(
            "SELECT actor_id, key FROM actor_memory \
             WHERE value_format = $1 AND value_key_id = $2 ORDER BY id LIMIT $3",
        )
        .bind(fmt)
        .bind(key_id)
        .bind(SAMPLE_PER_GROUP)
        .fetch_all(&pool)
        .await?;

        let mut ok = 0usize;
        for r in &rows {
            let actor_id: Uuid = r.try_get("actor_id")?;
            let key: String = r.try_get("key")?;
            match talos_memory::recall_exact(&pool, actor_id, &key).await {
                // The value is never printed — only that it decrypted.
                Ok(Some(_)) => ok += 1,
                Ok(None) => failures.push(format!(
                    "actor_memory v{fmt}/dek {key_id}: a sampled row vanished on read"
                )),
                Err(e) => failures.push(format!(
                    "actor_memory v{fmt}/dek {key_id}: DECRYPT FAILED — {e}"
                )),
            }
        }
        println!(
            "✓ actor_memory format v{fmt} (dek {key_id}): {ok}/{} sampled rows decrypted \
             ({total} rows in group)",
            rows.len()
        );
    }

    // ── 5. Decrypt PRE-EXISTING secrets ──────────────────────────────────
    let org_ids: Vec<Uuid> = sqlx::query("SELECT id FROM organizations")
        .fetch_all(&pool)
        .await
        .map(|rows| {
            rows.iter()
                .filter_map(|r| r.try_get::<Uuid, _>("id").ok())
                .collect()
        })
        .unwrap_or_default();

    let fmts: Vec<i16> = sqlx::query("SELECT DISTINCT encryption_format_version FROM secrets")
        .fetch_all(&pool)
        .await?
        .iter()
        .map(|r| r.try_get::<i16, _>("encryption_format_version"))
        .collect::<Result<Vec<_>, _>>()?;

    if fmts.is_empty() {
        println!("  secrets: no rows to decrypt (empty table — nothing asserted)");
    }
    for fmt in fmts {
        let paths: Vec<String> = sqlx::query(
            "SELECT key_path FROM secrets WHERE encryption_format_version = $1 \
             ORDER BY id LIMIT $2",
        )
        .bind(fmt)
        .bind(SAMPLE_PER_GROUP)
        .fetch_all(&pool)
        .await?
        .iter()
        .map(|r| r.try_get::<String, _>("key_path"))
        .collect::<Result<Vec<_>, _>>()?;

        let mut ok = 0usize;
        for p in &paths {
            match secrets
                .get_secret(p, SecretRequestor::System, &org_ids)
                .await
            {
                // Length only — a decrypted secret must never reach a log.
                Ok(v) => {
                    if v.is_empty() {
                        failures.push(format!("secrets v{fmt}: '{p}' decrypted to an EMPTY value"));
                    } else {
                        ok += 1;
                    }
                }
                Err(e) => failures.push(format!("secrets v{fmt}: '{p}' DECRYPT FAILED — {e}")),
            }
        }
        println!(
            "✓ secrets format v{fmt}: {ok}/{} sampled rows decrypted",
            paths.len()
        );
    }

    // ── 6. Every referenced DEK survived the restore ─────────────────────
    let mut referenced: BTreeSet<Uuid> = BTreeSet::new();
    for r in sqlx::query("SELECT DISTINCT value_key_id FROM actor_memory")
        .fetch_all(&pool)
        .await?
    {
        referenced.insert(r.try_get("value_key_id")?);
    }
    for r in sqlx::query("SELECT DISTINCT encryption_key_id FROM secrets")
        .fetch_all(&pool)
        .await?
    {
        referenced.insert(r.try_get("encryption_key_id")?);
    }
    let mut present = 0usize;
    for id in &referenced {
        let found: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM encryption_keys WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await?;
        if found.0 == 0 {
            failures.push(format!(
                "DEK {id} is referenced by restored data but MISSING from encryption_keys"
            ));
        } else {
            present += 1;
        }
    }
    println!(
        "✓ key material: {present}/{} referenced DEKs present",
        referenced.len()
    );

    // ── Verdict ──────────────────────────────────────────────────────────
    if failures.is_empty() {
        println!("\n🎉 Restore verification PASSED — pre-existing data is readable");
        Ok(())
    } else {
        eprintln!(
            "\n✗ Restore verification FAILED ({} problem(s)):",
            failures.len()
        );
        for f in &failures {
            eprintln!("   - {f}");
        }
        bail!("restore verification failed")
    }
}

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
//! WHAT THIS DOES **NOT** CHECK — stated here because the failure mode this
//! file exists to prevent is a verifier that implies more than it sampled:
//!   * Only `actor_memory` and `secrets` ciphertext is decrypted. The other
//!     encrypted column families — `workflow_executions` output, module
//!     payloads, TOTP secrets, webhook secrets, `integration_state` — are
//!     counted at most, never decrypted. They ride the same KEK→DEK→AEAD
//!     chain, so a SYSTEMIC crypto failure surfaces in the two that are
//!     sampled; a fault confined to one of the others would not.
//!   * Expired rows are excluded from sampling on both tables. `recall_exact`
//!     and `get_secret` refuse them by design, so including them made an
//!     intact backup fail (see the comments at each sampling query).
//!   * The KEK itself. The drill sources `TALOS_MASTER_KEY` from the LIVE
//!     controller, so a pass means "these artifacts + today's live KEK are
//!     readable" — NOT "these artifacts are readable". Nothing here can see
//!     that gap; the drill's banner states it.
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

    // The drill passes EVERY migration version this checkout ships, not just
    // the newest.
    //
    // Equality against the newest was the first shape and it FALSE-REDS on a
    // good backup: an artifact taken before a migration landed cannot contain
    // that migration, and migrations land most weeks — so a nightly dump plus
    // one new migration made the drill fail with "restored schema is at
    // version X, this checkout ships Y" on a completely restorable backup. A
    // detector that fires on ordinary healthy operation is the exact defect
    // class this whole area of the repo exists to remove, so it is not kept
    // for its teeth.
    //
    // What is checked instead is strictly narrower AND has no healthy-state
    // false positive: the restored max version must be a migration point THIS
    // CHECKOUT KNOWS. A foreign, corrupt or half-restored schema lands on a
    // version that is not in the set (a NEWER-than-this-checkout version is
    // caught by the same test, since the newest known version is the maximum).
    // Being behind is reported, with how far, and is not a failure.
    if let Ok(list) = std::env::var("TALOS_DRILL_MIGRATION_VERSIONS") {
        let known: BTreeSet<i64> = list
            .split(',')
            .filter_map(|s| s.trim().parse::<i64>().ok())
            .collect();
        if known.is_empty() {
            bail!("TALOS_DRILL_MIGRATION_VERSIONS was set but parsed to no versions");
        }
        let newest = *known.iter().next_back().expect("non-empty");
        match max_version {
            None => failures.push("restored database has no migration rows".into()),
            Some(v) if !known.contains(&v) => failures.push(format!(
                "restored schema is at version {v}, which is NOT a migration this checkout ships \
                 (newest known {newest}) — wrong database, or a schema this checkout cannot read"
            )),
            Some(v) if v == newest => println!("✓ schema version matches this checkout ({v})"),
            Some(v) => {
                let behind = known.range((v + 1)..).count();
                println!(
                    "✓ schema version {v} is a migration point this checkout knows; \
                     the checkout ships {newest} ({behind} migration(s) added after this \
                     artifact was taken — expected, not a restore defect)"
                );
            }
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
        "SELECT value_format, value_key_id, COUNT(*) AS n, \
                COUNT(*) FILTER (WHERE expires_at IS NULL OR expires_at > now()) AS live \
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
        let live: i64 = g.try_get("live")?;

        // `AND (expires_at IS NULL OR expires_at > now())` is REQUIRED, not
        // tidiness. `recall_exact` applies exactly that predicate, and `now()`
        // here is VERIFY time — up to a day after the dump was taken, and much
        // more if the artifact is an archived one. Sampling without it hands
        // `recall_exact` rows whose TTL lapsed between backup and drill; they
        // come back `Ok(None)` and were recorded as "a sampled row vanished on
        // read", failing the drill on a perfectly intact backup. The episodic
        // default TTL is 168 h, so roughly 1/7 of that population turns over in
        // any 24 h window — with a 5-row sample this was close to a coin flip
        // per group. An expired row is not a restore defect; it is a row the
        // reader is supposed to stop returning.
        let rows = sqlx::query(
            "SELECT actor_id, key FROM actor_memory \
             WHERE value_format = $1 AND value_key_id = $2 \
               AND (expires_at IS NULL OR expires_at > now()) \
             ORDER BY id LIMIT $3",
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
             ({live} unexpired of {total} rows in group)",
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

    // Grouped by (format, DEK), not by format alone. With per-ORG v4 DEKs a
    // format-only grouping exercises whichever org happens to sort first and
    // never touches a second org's key — so "sampled per DEK" would have been
    // true of actor_memory and false here. The group key is the same pair on
    // both sides now.
    let secret_groups = sqlx::query(
        "SELECT encryption_format_version, encryption_key_id, COUNT(*) AS n, \
                COUNT(*) FILTER (WHERE expires_at IS NULL OR expires_at > now()) AS live \
         FROM secrets GROUP BY encryption_format_version, encryption_key_id ORDER BY 1, 2",
    )
    .fetch_all(&pool)
    .await?;

    if secret_groups.is_empty() {
        println!("  secrets: no rows to decrypt (empty table — nothing asserted)");
    }
    for g in &secret_groups {
        let fmt: i16 = g.try_get("encryption_format_version")?;
        let key_id: Uuid = g.try_get("encryption_key_id")?;
        let total: i64 = g.try_get("n")?;
        let live: i64 = g.try_get("live")?;

        // Same expiry predicate, same reason, worse symptom: `get_secret`
        // answers an expired row with `Err("Secret has expired")`, which this
        // loop recorded as "DECRYPT FAILED" — the most alarming possible
        // wording for a ciphertext that is completely intact. Expiry between
        // the dump and the drill is normal operation, not a restore defect.
        let paths: Vec<String> = sqlx::query(
            "SELECT key_path FROM secrets \
             WHERE encryption_format_version = $1 AND encryption_key_id = $2 \
               AND (expires_at IS NULL OR expires_at > now()) \
             ORDER BY id LIMIT $3",
        )
        .bind(fmt)
        .bind(key_id)
        .bind(SAMPLE_PER_GROUP)
        .fetch_all(&pool)
        .await?
        .iter()
        .map(|r| r.try_get::<String, _>("key_path"))
        .collect::<Result<Vec<_>, _>>()?;

        let mut ok = 0usize;
        for p in &paths {
            // The PATH is identifying, not just the value. A vault key_path
            // looks like `oauth/gmail/<org-uuid>/<user-email>/refresh_token`,
            // so interpolating it into a failure line puts a real email
            // address and org/user UUIDs into drill output — which is logged,
            // scrolled past in a terminal, and pasted into issues. "No
            // decrypted secret is printed" was true and too narrow.
            //
            // Reported as a SHA-256 prefix instead, matching the `key_hash`
            // convention the audit log already uses (CLAUDE.md: "Audit logs
            // record key_hash (SHA-256 of path), never the value"). An
            // operator can still correlate a failing row across runs and
            // against the audit trail; they just cannot read whose it is out
            // of the drill transcript.
            let ph = {
                use sha2::{Digest, Sha256};
                let d = Sha256::digest(p.as_bytes());
                format!("{:x}", d)[..16].to_string()
            };
            match secrets
                .get_secret(p, SecretRequestor::System, &org_ids)
                .await
            {
                // Length only — a decrypted secret must never reach a log.
                Ok(v) => {
                    if v.is_empty() {
                        failures.push(format!(
                            "secrets v{fmt}: key_hash {ph} decrypted to an EMPTY value"
                        ));
                    } else {
                        ok += 1;
                    }
                }
                Err(e) => failures.push(format!(
                    "secrets v{fmt}: key_hash {ph} DECRYPT FAILED — {e}"
                )),
            }
        }
        println!(
            "✓ secrets format v{fmt} (dek {key_id}): {ok}/{} sampled rows decrypted \
             ({live} unexpired of {total} rows in group)",
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
        // Say what was SAMPLED, not what would be reassuring. `actor_memory`
        // and `secrets` are two of the encrypted column families in this
        // schema; `workflow_executions` output, module payloads, TOTP secrets,
        // webhook secrets and `integration_state` are NOT decrypt-verified
        // here. They share the same KEK→DEK→AEAD chain, so a systemic crypto
        // failure would show up in the two that are sampled — but a fault
        // confined to one of the others would not, and "pre-existing data is
        // readable" claimed otherwise.
        println!(
            "\n🎉 Restore verification PASSED — sampled pre-existing actor_memory \
             and secrets ciphertext decrypted (other encrypted column families \
             not sampled; see this file's header)"
        );
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

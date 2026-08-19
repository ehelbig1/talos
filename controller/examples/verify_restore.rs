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
//!   5. `ml_examples` — the irreplaceable family. Code is in git; a month of
//!      human labelling is not. Decrypted through the production
//!      `DatasetService::sample_examples` path so the AAD derivation cannot
//!      drift from the one the platform writes with.
//!   6. Referential integrity of the key material: every `encryption_key_id`
//!      referenced by data has a row in `encryption_keys`.
//!
//! CONTENT IS REPORTED, AND THE FAILURE LINE IS DRAWN PER FAMILY (2026-08-13,
//! corrected the same day). Until this change the `actor_memory` arm matched
//! `Ok(Some(_))` and counted it. Tightening that was right; the JUSTIFICATION
//! written beside it was wrong, and the first correction over-tightened.
//!
//! The stated reason was that `Ok(Some(Value::Null))` is what
//! `resolve_stored_value` returns for a row with no ciphertext, so accepting it
//! would let a half-restored table read as success. **That scenario cannot
//! occur.** In the restored schema `actor_memory.value_enc` and `value_key_id`
//! are `NOT NULL` (migration `20260424010000_actor_memory_value_drop_phase_b`),
//! `value_format` is `NOT NULL DEFAULT 0` (`20260528120000`), and the legacy
//! plaintext `value` column is dropped — so no real row can reach the
//! null-because-no-ciphertext path. A successful decrypt IS the readability
//! proof; there is no ciphertext-free row for it to be confused with.
//!
//! And treating a trivial plaintext as a FAILURE false-reds an intact backup.
//! `__memory_write__`'s `value` field **defaults to JSON `null`** (CLAUDE.md),
//! and `[]` / `{}` / `""` are legitimate stored payloads — a "nothing today"
//! result from a workflow that found no work. With only 5 rows sampled per
//! (format, DEK) group, one such row reds the drill on a perfectly good
//! backup: the exact detector-fires-on-healthy-operation class this file
//! removes elsewhere (the expiry predicate, the migration-version relaxation).
//!
//! So the line is drawn where the WRITER makes it meaningful:
//!   * `actor_memory` — a trivial plaintext is REPORTED and counted separately,
//!     never failed. The platform writes those on purpose.
//!   * `secrets` — an empty plaintext IS a failure. Nothing writes an empty
//!     OAuth token or an empty provider key; there is no "no secret today".
//!   * `ml_examples` — an empty features blob or label IS a failure, same
//!     reasoning: a training datum with no content is not a datum.
//! The decrypt itself failing (`Err`) or the row vanishing on read (`Ok(None)`)
//! remains fatal for every family — that is what "unreadable" actually is.
//!
//! The tightening is still strictly stronger than the `Ok(Some(_))` it
//! replaced: `Err` and `Ok(None)` were already caught, and now the plaintext is
//! inspected and reported rather than discarded.
//!
//! AND IT CANNOT PASS VACUOUSLY. The same arm printed "no rows to decrypt
//! (empty table — nothing asserted)" and returned success — so a restore that
//! moved zero encrypted rows was indistinguishable from one that moved them
//! all and read them back. Each family now reports an ELIGIBLE population
//! alongside its verified count and fails when eligible > 0 and verified == 0,
//! and the run fails outright when NOTHING anywhere was decrypted. See
//! `Tally` below for the exact rule and its stated limit — which applies to
//! EVERY family, not only `ml_examples`.
//!
//! WHAT THIS DOES **NOT** CHECK — stated here because the failure mode this
//! file exists to prevent is a verifier that implies more than it sampled:
//!   * Only `actor_memory`, `secrets` and `ml_examples` ciphertext is
//!     decrypted. The other encrypted column families —
//!     `workflow_executions` output, module payloads, TOTP secrets, webhook
//!     secrets, `integration_state` — are counted at most, never decrypted.
//!     They ride the same KEK→DEK→AEAD chain, so a SYSTEMIC crypto failure
//!     surfaces in the three that are sampled; a fault confined to one of the
//!     others would not.
//!   * Expired rows are excluded from sampling on `actor_memory` and
//!     `secrets`. `recall_exact` and `get_secret` refuse them by design, so
//!     including them made an intact backup fail (see the comments at each
//!     sampling query). `ml_examples` has no expiry.
//!   * Non-classification `ml_examples` rows. The sampler selects on
//!     `label_json ? 'label'`, so a regression dataset's ciphertext is never
//!     read here — and is excluded from that family's eligible count too, so
//!     it cannot trip the anti-vacuity rule either way.
//!   * The KEK's PROVENANCE. This binary decrypts with whatever
//!     `TALOS_MASTER_KEY` it is handed and cannot tell where that came from.
//!     Sourcing it from escrow rather than the live container is enforced by
//!     the DRILL (`scripts/drills/backup-restore.sh` step 0b), not here — so
//!     running this verifier by hand with a key copied out of a container
//!     proves the same thing it always did. That gate lives one layer up on
//!     purpose: this file's job is "is the ciphertext readable with this key",
//!     the drill's job is "is this key one a disaster survivor would have".
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

/// Rows sampled per label per `ml_examples` dataset. Small on purpose: the
/// question is "is this dataset's DEK+AAD readable", which is uniform across
/// the dataset, not "is row 4,821 individually intact".
const ML_SAMPLE_PER_LABEL: i64 = 2;

/// Per-family decrypt bookkeeping — the anti-vacuity machinery.
///
/// `eligible` is the count of rows a correct restore SHOULD have been able to
/// hand this verifier: unexpired for the TTL'd tables, label-bearing for
/// `ml_examples`. `verified` counts plaintexts that came back AND passed the
/// content assertion. The rule is then simply: `eligible > 0 && verified == 0`
/// is a failure, and a run where every family verified nothing is a failure
/// whatever the individual counts say.
///
/// STATED LIMIT, because a check that overstates itself is the defect this
/// file exists to remove: when `eligible` is 0 the family is SKIPPED, not
/// failed — and that applies to **every** family here, `secrets` and
/// `actor_memory` exactly as much as `ml_examples`. (The docs framed it only
/// around ML datasets, which reads as if the other two were covered. They are
/// not: a restore that moved zero `secrets` rows skips the same way.) Such a
/// restore is caught, if at all, by `pg_restore --exit-on-error` and by the row
/// counts printed above, not here. Making "eligible == 0" fatal per-family
/// would false-red every deployment that legitimately has no ML datasets — the
/// detector-fires-on-healthy-operation trade this repo has repeatedly refused.
/// The global floor below is the part that has no healthy-state false positive.
struct Tally {
    family: &'static str,
    eligible: i64,
    /// Rows whose ciphertext was successfully decrypted. This is the
    /// readability population and what the anti-vacuity rule reads.
    verified: usize,
    /// Of `verified`, how many carried a trivial plaintext. Reported, never
    /// failed — see `classify_decrypted_json`.
    trivial: usize,
}

impl Tally {
    fn new(family: &'static str) -> Self {
        Self {
            family,
            eligible: 0,
            verified: 0,
            trivial: 0,
        }
    }
}

/// Describe a decrypted plaintext that is present but carries no content.
///
/// Returns `Some(reason)` for JSON `null`, an empty/whitespace-only string, an
/// empty array or an empty object; `None` otherwise.
///
/// **This is a classifier, not an assertion**, and the distinction is the point.
/// Every one of those shapes is something the platform legitimately writes:
/// `__memory_write__`'s `value` defaults to JSON `null`, and `[]` is what a
/// workflow stores when it found nothing to report. Callers decide whether a
/// trivial plaintext is a defect for THEIR family — for `actor_memory` it is
/// not, and failing on it reds an intact backup.
fn classify_decrypted_json(v: &serde_json::Value) -> Option<&'static str> {
    match v {
        serde_json::Value::Null => Some("JSON null"),
        serde_json::Value::String(s) if s.trim().is_empty() => Some("empty/whitespace-only string"),
        serde_json::Value::Array(a) if a.is_empty() => Some("empty array"),
        serde_json::Value::Object(o) if o.is_empty() => Some("empty object"),
        _ => None,
    }
}

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

    let mut mem_tally = Tally::new("actor_memory");
    if groups.is_empty() {
        println!("  actor_memory: no rows present (eligible 0 — family SKIPPED, see Tally docs)");
    }
    for g in &groups {
        let fmt: i16 = g.try_get("value_format")?;
        // Read as `Option<Uuid>` and report, rather than `?`-ing a decode
        // error. `value_key_id` is `NOT NULL` in the schema this checkout
        // ships, so a NULL here means the RESTORED table does not match it —
        // which is a restore finding and deserves to be named. Bailing on the
        // raw sqlx decode error aborted the whole verifier with a message
        // ("mismatched types; Rust type `Uuid` is not compatible with SQL type
        // `UUID`") that says nothing about what an operator should do.
        let key_id: Uuid = match g.try_get::<Option<Uuid>, _>("value_key_id")? {
            Some(k) => k,
            None => {
                failures.push(format!(
                    "actor_memory v{fmt}: a group has a NULL value_key_id — the DEK reference \
                     did not survive the restore, so those rows name no key and can never be \
                     decrypted (the column is NOT NULL in this checkout's schema)"
                ));
                continue;
            }
        };
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

        mem_tally.eligible += live;

        let mut ok = 0usize;
        let mut trivial = 0usize;
        for r in &rows {
            let actor_id: Uuid = r.try_get("actor_id")?;
            let key: String = r.try_get("key")?;
            match talos_memory::recall_exact(&pool, actor_id, &key).await {
                // The value is never printed — only whether its CONTENT is
                // trivial. A trivial plaintext is NOT a failure here: the
                // `__memory_write__` protocol defaults `value` to JSON null and
                // `[]` is a legitimate "nothing today" payload, so failing on
                // one reds an intact backup. The decrypt succeeding is the
                // readability proof; see `classify_decrypted_json`.
                Ok(Some(row)) => {
                    ok += 1;
                    if classify_decrypted_json(&row.value).is_some() {
                        trivial += 1;
                    }
                }
                Ok(None) => failures.push(format!(
                    "actor_memory v{fmt}/dek {key_id}: a sampled row vanished on read"
                )),
                Err(e) => failures.push(format!(
                    "actor_memory v{fmt}/dek {key_id}: DECRYPT FAILED — {e}"
                )),
            }
        }
        mem_tally.verified += ok;
        mem_tally.trivial += trivial;
        // The marker reflects the RESULT. A leading `✓` was printed
        // unconditionally, so a group that decrypted 0 of 5 rows announced
        // itself with a tick and the failure only appeared further down.
        println!(
            "{} actor_memory format v{fmt} (dek {key_id}): {ok}/{} sampled rows decrypted{} \
             ({live} unexpired of {total} rows in group)",
            if !rows.is_empty() && ok == rows.len() {
                "✓"
            } else {
                "✗"
            },
            rows.len(),
            if trivial > 0 {
                format!(", {trivial} with a trivially-empty payload (not a defect)")
            } else {
                String::new()
            },
        );
    }

    // ── 5. Decrypt PRE-EXISTING secrets ──────────────────────────────────
    // NOT NULL: the previous `.filter_map(... .ok())` could only drop an org on
    // schema drift, and a dropped org is one whose secrets are never verified —
    // a verifier that silently narrows its own scope.
    let org_ids: Vec<Uuid> = sqlx::query("SELECT id FROM organizations")
        .fetch_all(&pool)
        .await?
        .iter()
        .map(|r| r.try_get::<Uuid, _>("id"))
        .collect::<std::result::Result<Vec<Uuid>, _>>()?;

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

    let mut secret_tally = Tally::new("secrets");
    if secret_groups.is_empty() {
        println!("  secrets: no rows present (eligible 0 — family SKIPPED, see Tally docs)");
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
                //
                // An EMPTY secret IS a failure, unlike a trivial actor_memory
                // payload: nothing writes an empty OAuth token or an empty
                // provider key, so there is no "no secret today" to false-red
                // on. See the header's per-family reasoning.
                Ok(v) => {
                    if v.trim().is_empty() {
                        failures.push(format!(
                            "secrets v{fmt}: key_hash {ph} decrypted to an EMPTY value"
                        ));
                    } else {
                        ok += 1;
                    }
                }
                // The ERROR TEXT carries the path too, and interpolating it
                // raw undid the `key_hash` change on the line right above:
                // `get_secret`'s expiry arm is
                // `anyhow!("Secret has expired: {}", key_path)`
                // (talos-secrets-manager/src/manager.rs:1460), so `{e}` put a
                // real email address and org/user UUIDs back into the drill
                // transcript. Hashing the path and then printing an error that
                // spells it out is a redaction that redacts nothing.
                Err(e) => {
                    let redacted = e
                        .to_string()
                        .replace(p.as_str(), &format!("<key_hash {ph}>"));
                    failures.push(format!(
                        "secrets v{fmt}: key_hash {ph} DECRYPT FAILED — {redacted}"
                    ))
                }
            }
        }
        secret_tally.eligible += live;
        secret_tally.verified += ok;
        println!(
            "{} secrets format v{fmt} (dek {key_id}): {ok}/{} sampled rows decrypted \
             with non-empty content ({live} unexpired of {total} rows in group)",
            if !paths.is_empty() && ok == paths.len() {
                "✓"
            } else {
                "✗"
            },
            paths.len()
        );
    }

    // ── 5b. Decrypt PRE-EXISTING ml_examples ─────────────────────────────
    // The irreplaceable family, and the reason this drill's stakes are what
    // they are: every other encrypted table holds something derivable from
    // code, configuration or a provider that can re-issue it. `ml_examples`
    // holds human labelling decisions. Nothing regenerates those.
    //
    // Decrypted through the PRODUCTION `DatasetService::sample_examples`, not
    // a local re-implementation of the AAD scheme. `ml_examples` binds AAD on
    // (`dataset_id`, `example_key`-or-`id`) — a re-derivation here would be a
    // second copy of that rule, free to drift from the writer's, and a drifted
    // copy fails CLOSED in a way that looks exactly like corrupt ciphertext.
    let mut ml_tally = Tally::new("ml_examples");
    {
        use talos_ml::dataset::DatasetService;
        let ds = DatasetService::new(secrets.clone());

        // Only datasets with label-bearing rows: `sample_examples` selects on
        // `label_json ? 'label'` and `decrypt_row` errors on a row without
        // one, so a regression dataset would be reported as a decrypt failure
        // when nothing is wrong with its ciphertext.
        let datasets = sqlx::query(
            "SELECT d.id, COUNT(e.id) AS n FROM ml_datasets d \
             JOIN ml_examples e ON e.dataset_id = d.id AND e.label_json ? 'label' \
             GROUP BY d.id ORDER BY d.id",
        )
        .fetch_all(&pool)
        .await?;

        if datasets.is_empty() {
            println!("  ml_examples: no label-bearing rows present (eligible 0 — family SKIPPED)");
        }
        for d in &datasets {
            let dataset_id: Uuid = d.try_get("id")?;
            let n: i64 = d.try_get("n")?;
            ml_tally.eligible += n;

            let mut conn = pool.acquire().await?;
            match ds
                .sample_examples(&mut conn, dataset_id, ML_SAMPLE_PER_LABEL)
                .await
            {
                Ok(samples) => {
                    let mut ok = 0usize;
                    for s in &samples {
                        // NEITHER the features nor the label is printed. The
                        // features are the source content the label was
                        // applied to (email bodies, alert text); the label is
                        // a category name but the pair is the training datum.
                        if s.features_text.trim().is_empty() {
                            failures.push(format!(
                                "ml_examples dataset {dataset_id}: example {} decrypted to \
                                 empty/whitespace-only features",
                                s.id
                            ));
                        } else if s.label.trim().is_empty() {
                            failures.push(format!(
                                "ml_examples dataset {dataset_id}: example {} decrypted with \
                                 an empty label",
                                s.id
                            ));
                        } else {
                            ok += 1;
                        }
                    }
                    if samples.is_empty() {
                        failures.push(format!(
                            "ml_examples dataset {dataset_id}: {n} label-bearing rows present \
                             but the sampler returned none"
                        ));
                    }
                    ml_tally.verified += ok;
                    println!(
                        "{} ml_examples dataset {dataset_id}: {ok}/{} sampled rows decrypted \
                         with non-empty features+label ({n} label-bearing rows in dataset)",
                        if !samples.is_empty() && ok == samples.len() {
                            "✓"
                        } else {
                            "✗"
                        },
                        samples.len()
                    );
                }
                // `sample_examples` fails the whole batch on the first bad
                // row (`?` inside its loop), which is the right shape here:
                // one unreadable row in a dataset means the DEK/AAD for that
                // dataset is wrong, not that one row is unlucky.
                Err(e) => failures.push(format!(
                    "ml_examples dataset {dataset_id}: DECRYPT FAILED — {e}"
                )),
            }
        }
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

    // ── 7. Anti-vacuity: the check must be able to fail ──────────────────
    // Everything above this line reports on what it found. This block is the
    // part that refuses to certify a run that found nothing — the property
    // whose absence made the old drill worthless at the level above.
    let tallies = [&mem_tally, &secret_tally, &ml_tally];
    println!("\n  decrypt coverage (eligible → decrypted):");
    for t in tallies {
        println!(
            "    {:<14} {:>8} → {:>6}{}{}",
            t.family,
            t.eligible,
            t.verified,
            if t.trivial > 0 {
                format!("  ({} trivially-empty payload(s))", t.trivial)
            } else {
                String::new()
            },
            // "[skipped]" applies to EVERY family with no eligible rows, not
            // just ml_examples — see `Tally`'s stated limit.
            if t.eligible == 0 { "   [skipped]" } else { "" }
        );
        if t.eligible > 0 && t.verified == 0 {
            failures.push(format!(
                "{}: {} row(s) were eligible for decryption and NOT ONE was read back — \
                 the restore did not preserve readable data for this family",
                t.family, t.eligible
            ));
        }
    }
    let total_verified: usize = tallies.iter().map(|t| t.verified).sum();
    if total_verified == 0 {
        // No family verified anything. Either the database is empty of
        // ciphertext or the key is wrong; both are answers a restore drill
        // must not report as success. Waivable ONLY for a genuinely fresh
        // deployment, because "we have no data yet" is a real state and
        // failing it forever would train operators to ignore the result.
        if std::env::var("TALOS_DRILL_ALLOW_NO_CIPHERTEXT").as_deref() == Ok("1") {
            println!(
                "⚠ nothing was decrypted anywhere — WAIVED by TALOS_DRILL_ALLOW_NO_CIPHERTEXT=1. \
                 This run proves the schema restored and NOTHING about readability."
            );
        } else {
            failures.push(
                "NOTHING was decrypted in any family — this run proves the schema restored and \
                 nothing whatsoever about whether the data is readable. That is the failure mode \
                 this verifier exists to make impossible. If the deployment genuinely holds no \
                 encrypted data yet, set TALOS_DRILL_ALLOW_NO_CIPHERTEXT=1 and accept that the \
                 drill certifies nothing about readability."
                    .into(),
            );
        }
    }

    // ── Verdict ──────────────────────────────────────────────────────────
    if failures.is_empty() {
        // Say what was SAMPLED, not what would be reassuring. `actor_memory`,
        // `secrets` and `ml_examples` are three of the encrypted column
        // families in this schema; `workflow_executions` output, module
        // payloads, TOTP secrets, webhook secrets and `integration_state` are
        // NOT decrypt-verified here. They share the same KEK→DEK→AEAD chain,
        // so a systemic crypto failure would show up in the three that are
        // sampled — but a fault confined to one of the others would not, and
        // "pre-existing data is readable" claimed otherwise.
        println!(
            "\n🎉 Restore verification PASSED — {total_verified} pre-existing ciphertext row(s) \
             across actor_memory / secrets / ml_examples decrypted \
             (other encrypted column families not sampled; see this file's header)"
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
